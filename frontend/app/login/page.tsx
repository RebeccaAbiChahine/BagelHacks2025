"use client";

import type React from "react";
import { useState, useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation"; // Changed from next/router
import { motion } from "framer-motion";
import { checkAuth } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { ArrowLeft } from "lucide-react";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await fetch("https://cvuebackend.onrender.com/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        alert(data.error || "Login failed");
      } else {
        // Store user data in localStorage
        localStorage.setItem("user", JSON.stringify(data.user));

        // Check account_type and redirect accordingly
        const accountType = data.user?.account_type || "candidate";
        if (!accountType) {
          console.error("No account type found in response:", data);
          alert("Login successful but account type is missing");
          return;
        }

        window.location.href = `/${accountType}/${
          accountType === "employer" ? "dashboard" : "cv-upload"
        }`;
      }
    } catch (error) {
      console.error("Login error:", error);
      alert("An error occurred during login.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    const checkCurrentAuth = async () => {
      const user = await checkAuth();
      if (user) {
        router.push(
          user.account_type === "employer"
            ? "/employer/dashboard"
            : "/candidate/dashboard"
        );
      }
    };
    checkCurrentAuth();
  }, [router]);

  const fadeIn = {
    hidden: { opacity: 0, y: 20 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.6 } },
  };

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <header className="container mx-auto py-6">
        <div className="flex items-center">
          <Link href="/" className="flex items-center gap-2">
            <ArrowLeft size={20} className="text-muted-foreground" />
            <span className="text-muted-foreground">Back to home</span>
          </Link>
        </div>
      </header>

      <main className="flex-1 flex items-center justify-center p-4">
        <motion.div
          className="w-full max-w-md"
          initial="hidden"
          animate="visible"
          variants={fadeIn}
        >
          <Card className="border-border shadow-sm">
            <CardHeader className="space-y-1">
              <div className="flex justify-center mb-2">
                <Link href="/" className="text-2xl font-bold text-primary">
                  CVue
                </Link>
              </div>
              <CardTitle className="text-2xl text-center">
                Sign in to your account
              </CardTitle>
              <CardDescription className="text-center">
                Enter your email and password to sign in
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="name@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                  />
                </div>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="password">Password</Label>
                    <Link
                      href="/forgot-password"
                      className="text-sm text-primary hover:underline"
                    >
                      Forgot password?
                    </Link>
                  </div>
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox id="remember" />
                  <Label htmlFor="remember" className="text-sm font-normal">
                    Remember me
                  </Label>
                </div>
                <Button type="submit" className="w-full" disabled={isLoading}>
                  {isLoading ? (
                    <span className="flex items-center justify-center">
                      <span className="h-4 w-4 border-2 border-current border-t-transparent rounded-full animate-spin mr-2"></span>
                      Signing in...
                    </span>
                  ) : (
                    "Sign In"
                  )}
                </Button>
              </form>
            </CardContent>
            <CardFooter className="flex flex-col space-y-4">
              <div className="text-center text-sm">
                Don't have an account?{" "}
                <Link href="/signup" className="text-primary hover:underline">
                  Sign up
                </Link>
              </div>
            </CardFooter>
          </Card>
        </motion.div>
      </main>
    </div>
  );
}
