# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Safe DateTime Tool.

Provides timezone-aware datetime operations with:
- Safe parsing (no arbitrary code)
- Timezone support
- Human-readable formatting
- Date arithmetic
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union

from atr.decorator import tool


class DateTimeTool:
    """
    Safe datetime operations.
    
    Features:
    - Timezone-aware operations
    - Safe date parsing
    - Human-readable formatting
    - Date arithmetic
    - No eval() or exec()
    
    Example:
        ```python
        dt = DateTimeTool(default_timezone="UTC")
        
        # Get current time
        now = dt.now()
        
        # Parse date
        date = dt.parse("2024-01-15T10:30:00Z")
        
        # Format date
        formatted = dt.format(date, "YYYY-MM-DD")
        
        # Add/subtract time
        future = dt.add(date, days=7, hours=2)
        ```
    """
    
    # Common format patterns
    FORMATS = {
        "iso": "%Y-%m-%dT%H:%M:%S%z",
        "date": "%Y-%m-%d",
        "time": "%H:%M:%S",
        "datetime": "%Y-%m-%d %H:%M:%S",
        "human": "%B %d, %Y at %I:%M %p",
        "short": "%m/%d/%Y",
        "rfc2822": "%a, %d %b %Y %H:%M:%S %z",
    }
    
    def __init__(self, default_timezone: str = "UTC"):
        """
        Initialize datetime tool.
        
        Args:
            default_timezone: Default timezone name
        """
        self.default_timezone = default_timezone
        self._tz_cache = {}
    
    def _get_timezone(self, tz_name: Optional[str] = None) -> timezone:
        """Get timezone object."""
        tz_name = tz_name or self.default_timezone
        
        if tz_name in self._tz_cache:
            return self._tz_cache[tz_name]
        
        # Try to get timezone
        if tz_name.upper() == "UTC":
            tz = timezone.utc
        else:
            try:
                import zoneinfo
                tz = zoneinfo.ZoneInfo(tz_name)
            except ImportError:
                # Fallback to UTC offset parsing
                if tz_name.startswith("+") or tz_name.startswith("-"):
                    hours = int(tz_name[:3])
                    minutes = int(tz_name[4:6]) if len(tz_name) > 4 else 0
                    tz = timezone(timedelta(hours=hours, minutes=minutes))
                else:
                    tz = timezone.utc
        
        self._tz_cache[tz_name] = tz
        return tz
    
    @tool(
        name="datetime_now",
        description="Get the current date and time",
        tags=["datetime", "safe"]
    )
    def now(self, timezone_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Get current datetime.
        
        Args:
            timezone_name: Timezone name (default: UTC)
        
        Returns:
            Dict with current datetime info
        """
        try:
            tz = self._get_timezone(timezone_name)
            now = datetime.now(tz)
            
            return {
                "success": True,
                "iso": now.isoformat(),
                "timestamp": now.timestamp(),
                "year": now.year,
                "month": now.month,
                "day": now.day,
                "hour": now.hour,
                "minute": now.minute,
                "second": now.second,
                "weekday": now.strftime("%A"),
                "timezone": str(tz)
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @tool(
        name="datetime_parse",
        description="Parse a date/time string into components",
        tags=["datetime", "parse", "safe"]
    )
    def parse(
        self,
        date_string: str,
        format: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Parse datetime string.
        
        Args:
            date_string: Date string to parse
            format: Optional strptime format or preset name
        
        Returns:
            Dict with parsed datetime
        """
        try:
            # Try preset formats first
            if format and format.lower() in self.FORMATS:
                fmt = self.FORMATS[format.lower()]
                dt = datetime.strptime(date_string, fmt)
            elif format:
                dt = datetime.strptime(date_string, format)
            else:
                # Try common formats
                for fmt in [
                    "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%d",
                    "%m/%d/%Y",
                    "%d/%m/%Y",
                    "%B %d, %Y",
                ]:
                    try:
                        dt = datetime.strptime(date_string, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    return {
                        "success": False,
                        "error": f"Could not parse date: {date_string}"
                    }
            
            # Ensure timezone
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=self._get_timezone())
            
            return {
                "success": True,
                "iso": dt.isoformat(),
                "timestamp": dt.timestamp(),
                "year": dt.year,
                "month": dt.month,
                "day": dt.day,
                "hour": dt.hour,
                "minute": dt.minute,
                "second": dt.second,
                "weekday": dt.strftime("%A")
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @tool(
        name="datetime_format",
        description="Format a datetime into a string",
        tags=["datetime", "format", "safe"]
    )
    def format(
        self,
        iso_datetime: str,
        format: str = "human"
    ) -> Dict[str, Any]:
        """
        Format datetime to string.
        
        Args:
            iso_datetime: ISO format datetime string
            format: Output format (preset name or strftime format)
        
        Returns:
            Dict with formatted string
        """
        try:
            # Parse input
            dt = datetime.fromisoformat(iso_datetime.replace("Z", "+00:00"))
            
            # Get format
            if format.lower() in self.FORMATS:
                fmt = self.FORMATS[format.lower()]
            else:
                fmt = format
            
            formatted = dt.strftime(fmt)
            
            return {
                "success": True,
                "formatted": formatted,
                "format_used": fmt
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @tool(
        name="datetime_add",
        description="Add time to a datetime",
        tags=["datetime", "arithmetic", "safe"]
    )
    def add(
        self,
        iso_datetime: str,
        years: int = 0,
        months: int = 0,
        weeks: int = 0,
        days: int = 0,
        hours: int = 0,
        minutes: int = 0,
        seconds: int = 0
    ) -> Dict[str, Any]:
        """
        Add time to datetime.
        
        Args:
            iso_datetime: ISO format datetime
            years: Years to add
            months: Months to add
            weeks: Weeks to add
            days: Days to add
            hours: Hours to add
            minutes: Minutes to add
            seconds: Seconds to add
        
        Returns:
            Dict with new datetime
        """
        try:
            dt = datetime.fromisoformat(iso_datetime.replace("Z", "+00:00"))
            
            # Add using timedelta (doesn't handle years/months)
            delta = timedelta(
                weeks=weeks,
                days=days,
                hours=hours,
                minutes=minutes,
                seconds=seconds
            )
            
            new_dt = dt + delta
            
            # Handle years and months manually
            if years or months:
                new_year = new_dt.year + years
                new_month = new_dt.month + months
                
                # Handle month overflow
                while new_month > 12:
                    new_month -= 12
                    new_year += 1
                while new_month < 1:
                    new_month += 12
                    new_year -= 1
                
                # Handle day overflow for short months
                import calendar
                max_day = calendar.monthrange(new_year, new_month)[1]
                new_day = min(new_dt.day, max_day)
                
                new_dt = new_dt.replace(year=new_year, month=new_month, day=new_day)
            
            return {
                "success": True,
                "original": iso_datetime,
                "result": new_dt.isoformat(),
                "added": {
                    "years": years,
                    "months": months,
                    "weeks": weeks,
                    "days": days,
                    "hours": hours,
                    "minutes": minutes,
                    "seconds": seconds
                }
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @tool(
        name="datetime_diff",
        description="Calculate difference between two datetimes",
        tags=["datetime", "arithmetic", "safe"]
    )
    def diff(
        self,
        datetime1: str,
        datetime2: str
    ) -> Dict[str, Any]:
        """
        Calculate difference between datetimes.
        
        Args:
            datetime1: First datetime (ISO format)
            datetime2: Second datetime (ISO format)
        
        Returns:
            Dict with difference in various units
        """
        try:
            dt1 = datetime.fromisoformat(datetime1.replace("Z", "+00:00"))
            dt2 = datetime.fromisoformat(datetime2.replace("Z", "+00:00"))
            
            delta = dt2 - dt1
            total_seconds = delta.total_seconds()
            
            return {
                "success": True,
                "days": delta.days,
                "total_seconds": total_seconds,
                "total_minutes": total_seconds / 60,
                "total_hours": total_seconds / 3600,
                "human_readable": self._format_timedelta(delta)
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _format_timedelta(self, delta: timedelta) -> str:
        """Format timedelta as human readable string."""
        total_seconds = int(abs(delta.total_seconds()))
        
        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        
        parts = []
        if days:
            parts.append(f"{days} day{'s' if days != 1 else ''}")
        if hours:
            parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
        if minutes:
            parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
        if seconds or not parts:
            parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")
        
        result = ", ".join(parts)
        if delta.total_seconds() < 0:
            result = f"-{result}"
        
        return result
    
    @tool(
        name="datetime_convert_timezone",
        description="Convert datetime to a different timezone",
        tags=["datetime", "timezone", "safe"]
    )
    def convert_timezone(
        self,
        iso_datetime: str,
        to_timezone: str
    ) -> Dict[str, Any]:
        """
        Convert datetime to different timezone.
        
        Args:
            iso_datetime: ISO format datetime
            to_timezone: Target timezone name
        
        Returns:
            Dict with converted datetime
        """
        try:
            dt = datetime.fromisoformat(iso_datetime.replace("Z", "+00:00"))
            target_tz = self._get_timezone(to_timezone)
            
            converted = dt.astimezone(target_tz)
            
            return {
                "success": True,
                "original": iso_datetime,
                "converted": converted.isoformat(),
                "timezone": to_timezone
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @tool(
        name="datetime_is_before",
        description="Check if one datetime is before another",
        tags=["datetime", "compare", "safe"]
    )
    def is_before(self, datetime1: str, datetime2: str) -> Dict[str, Any]:
        """Check if datetime1 is before datetime2."""
        try:
            dt1 = datetime.fromisoformat(datetime1.replace("Z", "+00:00"))
            dt2 = datetime.fromisoformat(datetime2.replace("Z", "+00:00"))
            
            return {
                "success": True,
                "result": dt1 < dt2,
                "datetime1": datetime1,
                "datetime2": datetime2
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
