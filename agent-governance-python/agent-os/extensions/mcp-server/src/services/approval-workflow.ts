// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Approval Workflow Service
 * 
 * Manages human-in-the-loop approval requests for sensitive agent actions.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import {
  ApprovalRequest,
  ApprovalStatus,
  RequestApprovalInput,
} from '../types/index.js';

export class ApprovalWorkflow {
  private dataDir: string;
  private approvalsDir: string;
  
  constructor(dataDir: string) {
    this.dataDir = dataDir;
    this.approvalsDir = path.join(dataDir, 'approvals');
  }
  
  /**
   * Ensure data directory exists.
   */
  private async ensureDir(): Promise<void> {
    await fs.mkdir(this.approvalsDir, { recursive: true });
  }
  
  /**
   * Create a new approval request.
   */
  async createRequest(input: RequestApprovalInput): Promise<ApprovalRequest> {
    await this.ensureDir();
    
    const now = new Date();
    const expiresAt = new Date(now.getTime() + input.expiresInHours * 60 * 60 * 1000);
    
    const request: ApprovalRequest = {
      id: uuidv4(),
      agentId: input.agentId,
      action: input.action,
      description: input.description,
      riskLevel: this.assessRiskLevel(input.action, input.description),
      requestedBy: 'system', // Would come from auth context
      requestedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      status: 'pending',
      approvers: input.approvers.map(email => ({ email })),
      approvals: [],
      metadata: {},
    };
    
    await this.saveRequest(request);
    
    // In production, would send notifications here
    await this.sendNotifications(request);
    
    return request;
  }
  
  /**
   * Assess risk level based on action type.
   */
  private assessRiskLevel(action: string, description: string): ApprovalRequest['riskLevel'] {
    const lowerAction = action.toLowerCase();
    const lowerDesc = description.toLowerCase();
    
    // Critical risk actions
    if (
      lowerAction.includes('delete') ||
      lowerAction.includes('drop') ||
      lowerDesc.includes('production') ||
      lowerDesc.includes('financial')
    ) {
      return 'critical';
    }
    
    // High risk actions
    if (
      lowerAction.includes('update') ||
      lowerAction.includes('modify') ||
      lowerAction.includes('external') ||
      lowerDesc.includes('customer') ||
      lowerDesc.includes('sensitive')
    ) {
      return 'high';
    }
    
    // Medium risk actions
    if (
      lowerAction.includes('create') ||
      lowerAction.includes('send') ||
      lowerAction.includes('post')
    ) {
      return 'medium';
    }
    
    return 'low';
  }
  
  /**
   * Send notifications to approvers.
   */
  private async sendNotifications(request: ApprovalRequest): Promise<void> {
    // In production, would integrate with email/Slack/etc.
    // For now, just log
    console.log(`[Approval Request ${request.id}] Notifications would be sent to:`, 
      request.approvers.map(a => a.email).join(', '));
  }
  
  /**
   * Save approval request to disk.
   */
  private async saveRequest(request: ApprovalRequest): Promise<void> {
    const filePath = path.join(this.approvalsDir, `${request.id}.json`);
    await fs.writeFile(filePath, JSON.stringify(request, null, 2));
  }
  
  /**
   * Get approval request by ID.
   */
  async getRequest(id: string): Promise<ApprovalRequest | null> {
    try {
      const filePath = path.join(this.approvalsDir, `${id}.json`);
      const content = await fs.readFile(filePath, 'utf-8');
      return JSON.parse(content) as ApprovalRequest;
    } catch {
      return null;
    }
  }
  
  /**
   * Get all pending requests for an agent.
   */
  async getPendingRequests(agentId: string): Promise<ApprovalRequest[]> {
    await this.ensureDir();
    
    try {
      const files = await fs.readdir(this.approvalsDir);
      const requests: ApprovalRequest[] = [];
      
      for (const file of files) {
        if (file.endsWith('.json')) {
          const content = await fs.readFile(path.join(this.approvalsDir, file), 'utf-8');
          const request = JSON.parse(content) as ApprovalRequest;
          
          if (request.agentId === agentId && request.status === 'pending') {
            // Check if expired
            if (new Date(request.expiresAt) < new Date()) {
              request.status = 'expired';
              await this.saveRequest(request);
            } else {
              requests.push(request);
            }
          }
        }
      }
      
      return requests;
    } catch {
      return [];
    }
  }
  
  /**
   * Record an approval decision.
   */
  async recordApproval(
    requestId: string,
    approverEmail: string,
    decision: 'approved' | 'rejected',
    comment?: string
  ): Promise<ApprovalRequest> {
    const request = await this.getRequest(requestId);
    if (!request) {
      throw new Error(`Approval request not found: ${requestId}`);
    }
    
    if (request.status !== 'pending') {
      throw new Error(`Request is no longer pending: ${request.status}`);
    }
    
    // Check if approver is authorized
    const isAuthorized = request.approvers.some(a => a.email === approverEmail);
    if (!isAuthorized) {
      throw new Error(`Not authorized to approve this request: ${approverEmail}`);
    }
    
    // Check if already approved/rejected by this approver
    const alreadyApproved = request.approvals.some(a => a.approver === approverEmail);
    if (alreadyApproved) {
      throw new Error(`Already recorded decision from: ${approverEmail}`);
    }
    
    // Record the approval
    request.approvals.push({
      approver: approverEmail,
      decision,
      comment,
      timestamp: new Date().toISOString(),
    });
    
    // Determine final status
    if (decision === 'rejected') {
      request.status = 'rejected';
    } else if (this.checkApprovalQuorum(request)) {
      request.status = 'approved';
    }
    
    await this.saveRequest(request);
    
    return request;
  }
  
  /**
   * Check if approval quorum is met.
   */
  private checkApprovalQuorum(request: ApprovalRequest): boolean {
    const approvals = request.approvals.filter(a => a.decision === 'approved');
    
    // Default quorum rules based on risk level
    switch (request.riskLevel) {
      case 'critical':
        // Requires 2+ approvals for critical actions
        return approvals.length >= 2;
      case 'high':
        // Requires 2 approvals OR 1 from senior approver
        return approvals.length >= 2 || approvals.some(a => 
          request.approvers.find(ap => ap.email === a.approver)?.role === 'senior'
        );
      default:
        // Single approval sufficient
        return approvals.length >= 1;
    }
  }
  
  /**
   * Cancel an approval request.
   */
  async cancelRequest(requestId: string): Promise<void> {
    const request = await this.getRequest(requestId);
    if (!request) {
      throw new Error(`Approval request not found: ${requestId}`);
    }
    
    request.status = 'cancelled';
    await this.saveRequest(request);
  }
  
  /**
   * Check if an action is approved for execution.
   */
  async isApproved(requestId: string): Promise<boolean> {
    const request = await this.getRequest(requestId);
    if (!request) {
      return false;
    }
    
    // Check expiration
    if (new Date(request.expiresAt) < new Date()) {
      if (request.status === 'pending') {
        request.status = 'expired';
        await this.saveRequest(request);
      }
      return false;
    }
    
    return request.status === 'approved';
  }
  
  /**
   * Get approval status summary.
   */
  async getStatusSummary(requestId: string): Promise<{
    status: ApprovalStatus;
    approvalCount: number;
    rejectionCount: number;
    pendingCount: number;
    expiresIn: string;
  }> {
    const request = await this.getRequest(requestId);
    if (!request) {
      throw new Error(`Approval request not found: ${requestId}`);
    }
    
    const approvals = request.approvals.filter(a => a.decision === 'approved').length;
    const rejections = request.approvals.filter(a => a.decision === 'rejected').length;
    const pending = request.approvers.length - request.approvals.length;
    
    const expiresAt = new Date(request.expiresAt);
    const now = new Date();
    const diffMs = expiresAt.getTime() - now.getTime();
    const diffHours = Math.max(0, Math.floor(diffMs / (1000 * 60 * 60)));
    const diffMinutes = Math.max(0, Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60)));
    
    return {
      status: request.status,
      approvalCount: approvals,
      rejectionCount: rejections,
      pendingCount: pending,
      expiresIn: `${diffHours}h ${diffMinutes}m`,
    };
  }
}
