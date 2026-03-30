<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Private Endpoint Deployment Examples

Deploy AGT governance APIs behind private endpoints for zero-trust network access.

## Azure Private Endpoint

### Bicep Template

```bicep
@description('AGT governance API private endpoint')
param vnetName string = 'agt-vnet'
param subnetName string = 'pe-subnet'
param location string = resourceGroup().location

resource vnet 'Microsoft.Network/virtualNetworks@2023-09-01' existing = {
  name: vnetName
}

resource peSubnet 'Microsoft.Network/virtualNetworks/subnets@2023-09-01' existing = {
  parent: vnet
  name: subnetName
}

resource agtPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-09-01' = {
  name: 'pe-agt-governance'
  location: location
  properties: {
    subnet: {
      id: peSubnet.id
    }
    privateLinkServiceConnections: [
      {
        name: 'agt-governance-connection'
        properties: {
          privateLinkServiceId: agtService.id
          groupIds: ['agt-api']
        }
      }
    ]
  }
}

resource privateDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.governance.azure.com'
  location: 'global'
}

resource dnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: privateDnsZone
  name: 'agt-dns-link'
  location: 'global'
  properties: {
    virtualNetwork: { id: vnet.id }
    registrationEnabled: false
  }
}

resource dnsRecord 'Microsoft.Network/privateDnsZones/A@2020-06-01' = {
  parent: privateDnsZone
  name: 'agt-governance'
  properties: {
    ttl: 300
    aRecords: [
      { ipv4Address: agtPrivateEndpoint.properties.customDnsConfigs[0].ipAddresses[0] }
    ]
  }
}
```

### NSG Rules for PE Subnet

```bicep
resource peNsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'nsg-pe-subnet'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowAKSToAGT'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '10.0.1.0/24'  // AKS subnet
          destinationAddressPrefix: '10.0.2.0/24'  // PE subnet
          destinationPortRange: '443'
          sourcePortRange: '*'
        }
      }
      {
        name: 'DenyAllInbound'
        properties: {
          priority: 4096
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
          sourcePortRange: '*'
        }
      }
    ]
  }
}
```

## AWS PrivateLink

### Terraform — VPC Endpoint Service

```hcl
# NLB for AGT governance service
resource "aws_lb" "agt_nlb" {
  name               = "agt-governance-nlb"
  internal           = true
  load_balancer_type = "network"
  subnets            = var.private_subnet_ids

  tags = { Service = "agt-governance" }
}

resource "aws_lb_target_group" "agt_tg" {
  name     = "agt-governance-tg"
  port     = 443
  protocol = "TLS"
  vpc_id   = var.vpc_id

  health_check {
    protocol = "HTTPS"
    path     = "/healthz"
    port     = 443
  }
}

resource "aws_lb_listener" "agt_listener" {
  load_balancer_arn = aws_lb.agt_nlb.arn
  port              = 443
  protocol          = "TLS"
  certificate_arn   = var.acm_cert_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.agt_tg.arn
  }
}

# VPC Endpoint Service (provider side)
resource "aws_vpc_endpoint_service" "agt" {
  acceptance_required        = true
  network_load_balancer_arns = [aws_lb.agt_nlb.arn]

  allowed_principals = var.allowed_consumer_arns

  tags = { Name = "agt-governance-endpoint-service" }
}

# Interface Endpoint (consumer side)
resource "aws_vpc_endpoint" "agt_consumer" {
  vpc_id              = var.consumer_vpc_id
  service_name        = aws_vpc_endpoint_service.agt.service_name
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.consumer_subnet_ids
  security_group_ids  = [aws_security_group.agt_endpoint_sg.id]
  private_dns_enabled = true
}

resource "aws_security_group" "agt_endpoint_sg" {
  name_prefix = "agt-endpoint-"
  vpc_id      = var.consumer_vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.consumer_vpc_cidr]
  }
}
```

## GCP Private Service Connect

### Service Attachment (Producer)

```hcl
# Internal load balancer for AGT
resource "google_compute_forwarding_rule" "agt_ilb" {
  name                  = "agt-governance-ilb"
  region                = var.region
  load_balancing_scheme = "INTERNAL"
  backend_service       = google_compute_region_backend_service.agt.id
  ports                 = [443]
  network               = var.vpc_network
  subnetwork            = var.producer_subnet
}

# PSC subnet (dedicated for NAT)
resource "google_compute_subnetwork" "psc_nat" {
  name          = "agt-psc-nat-subnet"
  region        = var.region
  network       = var.vpc_network
  ip_cidr_range = "10.100.0.0/24"
  purpose       = "PRIVATE_SERVICE_CONNECT"
}

# Service attachment
resource "google_compute_service_attachment" "agt" {
  name                  = "agt-governance-psc"
  region                = var.region
  connection_preference = "ACCEPT_MANUAL"
  nat_subnets           = [google_compute_subnetwork.psc_nat.id]
  target_service        = google_compute_forwarding_rule.agt_ilb.id

  consumer_accept_lists {
    project_id_or_num = var.consumer_project_id
    connection_limit  = 10
  }
}
```

### Consumer Endpoint

```hcl
# Reserve IP for PSC endpoint
resource "google_compute_address" "psc_endpoint" {
  name         = "agt-psc-endpoint-ip"
  region       = var.region
  subnetwork   = var.consumer_subnet
  address_type = "INTERNAL"
}

# PSC endpoint
resource "google_compute_forwarding_rule" "psc_consumer" {
  name                  = "agt-psc-consumer"
  region                = var.region
  load_balancing_scheme = ""
  ip_address            = google_compute_address.psc_endpoint.id
  network               = var.consumer_vpc
  target                = google_compute_service_attachment.agt.id
}

# DNS routing
resource "google_dns_managed_zone" "agt_private" {
  name        = "agt-governance-private"
  dns_name    = "governance.internal."
  visibility  = "private"

  private_visibility_config {
    networks {
      network_url = var.consumer_vpc
    }
  }
}

resource "google_dns_record_set" "agt_endpoint" {
  managed_zone = google_dns_managed_zone.agt_private.name
  name         = "agt.governance.internal."
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_address.psc_endpoint.address]
}
```

### Firewall Rules

```hcl
resource "google_compute_firewall" "allow_psc" {
  name    = "allow-agt-psc"
  network = var.consumer_vpc

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = [var.consumer_subnet_cidr]
  target_tags   = ["agt-consumer"]
}
```
