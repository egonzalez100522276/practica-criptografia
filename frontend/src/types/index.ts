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
  status: "pending" | "completed";
  createdBy: string;
  assignedTo: string;
  createdAt: string;
  completedAt?: string;
}

export type ViewType = "login" | "register" | "dashboard" | "admin";
