export type UserRole = 'hr_admin' | 'board' | 'employee' | 'teacher';

export type AttendanceStatus =
  | 'Present'
  | 'Late'
  | 'Very Late'
  | 'Absent'
  | 'Early Leave'
  | 'On Leave';

export type DeviceStatus = 'ONLINE' | 'OFFLINE' | 'SYNCING' | 'ERROR';

export type LeaveStatus = 'PENDING' | 'APPROVED' | 'REJECTED';

export type LeaveType =
  | 'Annual Leave'
  | 'Sick Leave'
  | 'Emergency Leave'
  | 'Official Mission'
  | 'Training / Workshop';

export interface User {
  id: string;
  username: string;
  name: string;
  email: string;
  role: UserRole;
  password?: string;
  departmentId?: string;
  teacherId?: string;
  avatar?: string;
  phone?: string;
  jobTitle?: string;
  lastLogin?: string;
  lastLoginIp?: string;
}

export interface Department {
  id: string;
  name: string;
  code: string;
  headTeacherId: string;
  headTeacherName: string;
  building: string;
  room: string;
  totalTeachers: number;
  presentToday?: number;
  lateToday?: number;
  onLeaveToday?: number;
  absentToday?: number;
  attendancePercentage?: number;
}

export interface Schedule {
  id: string;
  name: string;
  startTime: string; // e.g. "07:30"
  endTime: string; // e.g. "15:00"
  gracePeriodMinutes: number; // e.g. 10 mins
  lateThresholdMinutes: number; // e.g. 40 mins
  workingDays: string[];
  description?: string;
}

export interface Teacher {
  id: string;
  employeeId: string;
  fullName: string;
  email: string;
  phone: string;
  departmentId: string;
  departmentName: string;
  position: string;
  hireDate: string;
  scheduleId: string;
  accountStatus: 'Active' | 'Suspended' | 'On Leave';
  fingerprintStatus: 'Registered' | 'Not Registered';
  fingerprintRegisteredAt?: string;
  fingerprintDeviceId?: string;
  avatar?: string;
  nationalId?: string;
  gender: 'Male' | 'Female';
  username?: string;
  password?: string;
  plainPassword?: string;
}

export interface AttendanceRecord {
  id: string;
  teacherId: string;
  teacherName: string;
  employeeId: string;
  departmentId: string;
  departmentName: string;
  date: string; // YYYY-MM-DD
  scheduledStartTime: string;
  scheduledEndTime: string;
  checkInTime: string | null;
  checkOutTime: string | null;
  rawCheckInTimestamp?: string;
  rawCheckOutTimestamp?: string;
  status: AttendanceStatus;
  lateDurationMinutes: number;
  earlyLeaveMinutes: number;
  deviceId?: string;
  deviceName?: string;
  verificationMethod: 'Fingerprint' | 'Manual Correction' | 'System Automated';
  isManualCorrection?: boolean;
  correctionReason?: string;
  correctedBy?: string;
  correctedAt?: string;
  notes?: string;
}

export interface AttendanceEvent {
  id: string;
  timestamp: string;
  displayTime: string;
  teacherId: string;
  teacherName: string;
  employeeId: string;
  departmentName: string;
  deviceId: string;
  deviceName: string;
  eventType: 'CHECK_IN' | 'CHECK_OUT';
  statusCalculated: AttendanceStatus;
  isSyncedFromOffline?: boolean;
  confidenceScore: number;
}

export interface FingerprintDevice {
  id: string;
  name: string;
  deviceModel: string;
  location: string;
  status: DeviceStatus;
  ipAddress: string;
  macAddress: string;
  lastSync: string;
  registeredCount: number;
  pendingEventsCount: number;
  firmwareVersion: string;
  port: number;
  isEntranceGate: boolean;
}

export interface LeaveRequest {
  id: string;
  teacherId: string;
  teacherName: string;
  employeeId: string;
  departmentId: string;
  departmentName: string;
  leaveType: LeaveType;
  startDate: string;
  endDate: string;
  daysCount: number;
  reason: string;
  status: LeaveStatus;
  appliedAt: string;
  reviewedAt?: string;
  reviewedBy?: string;
  rejectionReason?: string;
  attachmentName?: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  action: string;
  entity: string;
  entityId: string;
  actorName: string;
  actorRole: string;
  details: string;
  ipAddress: string;
  category?: 'AUTH' | 'SECURITY' | 'ATTENDANCE' | 'BIOMETRIC' | 'LEAVE' | 'FACULTY' | 'SYSTEM';
  severity?: 'SUCCESS' | 'WARNING' | 'ALERT' | 'INFO';
  metadata?: {
    userAgent?: string;
    browser?: string;
    os?: string;
    attemptedUsername?: string;
    attemptedPasswordMasked?: string;
    statusReason?: string;
    targetTeacherName?: string;
    targetTeacherId?: string;
    decryptedBy?: string;
    previousState?: any;
    newState?: any;
    [key: string]: any;
  };
}

export interface AuthResponse {
  success: boolean;
  user: User;
  token: string;
  auditLog?: AuditLog;
}

export interface NotificationItem {
  id: string;
  timestamp: string;
  title: string;
  message: string;
  type: 'INFO' | 'WARNING' | 'ALERT' | 'SUCCESS';
  targetRole?: UserRole | 'ALL';
  targetTeacherId?: string;
  isRead: boolean;
  link?: string;
}

export interface SystemSettings {
  schoolName: string;
  campusName: string;
  academicYear: string;
  defaultStartTime: string;
  defaultEndTime: string;
  defaultGracePeriodMinutes: number;
  defaultLateThresholdMinutes: number;
  requireFingerprintVerification: boolean;
  allowOfflineDeviceQueue: boolean;
  autoCheckoutAtMidnight: boolean;
  notificationOnLateArrival: boolean;
  adminAlertMissingAttendance: boolean;
}

export interface DashboardStats {
  totalTeachers: number;
  presentToday: number;
  lateToday: number;
  absentToday: number;
  onLeaveToday: number;
  attendancePercentage: number;
  registeredFingerprints: number;
  devicesOnlineCount: number;
  totalDevicesCount: number;
  onlineDevicesCount?: number;
}
