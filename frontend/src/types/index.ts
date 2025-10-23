export interface User {
  id: string;
  username: string;
  email: string;
  role: "agent" | "leader";
}

export interface Mission {
  id: string;
  title: string;
  description: string;
  createdBy: string;
  assignedTo: string;
  createdAt: string;
}

export interface MissionForm {
  title: string;
  description: string;
}

export type ViewType = "login" | "register" | "dashboard" | "admin";
