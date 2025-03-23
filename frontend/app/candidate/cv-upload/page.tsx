"use client";

import type React from "react";
import { useState, useRef, useEffect } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { checkAuth, User } from "@/lib/auth";
import { Modal } from "@/components/ui/modal";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Upload,
  FileText,
  CheckCircle,
  AlertCircle,
  Info,
  Search,
  TrendingUp,
} from "lucide-react";
import CandidateNavbar from "@/components/candidate-navbar";

export default function CVUploadPage() {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  
  useEffect(() => {
    async function validateAuth() {
      const userData = await checkAuth();
      if (!userData) {
        router.push('/login');
        return;
      }
      setUser(userData);
    }
    validateAuth();
  }, [router]);

  const [uploadState, setUploadState] = useState<
    "idle" | "uploading" | "success" | "error"
  >("idle");
  const [dragActive, setDragActive] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [showCV, setShowCV] = useState(false);

  const deleteCV = async (): Promise<void> => {
    try {
      const response = await fetch("https://cvuebackend.onrender.com/candidate/cv-delete", {
        method: "POST",
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        mode: 'cors',
      });

      if (response.ok) {
        const data = await response.json();
        alert(data.message);
        setUploadState("idle"); 
      } else {
        const errorText = await response.text();
        console.error("Delete error! Status:", response.status, "Response text:", errorText);
        alert("Failed to delete CV: " + errorText);
      }
    } catch (e) {
      console.error("Network error:", e);
      alert("Network error: Unable to connect to the server. Make sure the backend is running.");
    }
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      handleFile(e.target.files[0]);
    }
  };

  const handleFile = async (file: File) => {
    // Validate file type
    const allowedTypes = ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    if (!allowedTypes.includes(file.type)) {
      alert('Please upload a PDF or Word document');
      return;
    }

    // Validate file size (5MB)
    if (file.size > 5 * 1024 * 1024) {
      alert('File size must be less than 5MB');
      return;
    }

    const formData = new FormData();
    formData.append("cv", file);

    setUploadState("uploading");

    try {
      const response = await fetch("https://cvuebackend.onrender.com/candidate/cv-upload-api", {
        method: "POST",
        body: formData,
        credentials: 'include',
        mode: 'cors'
      });

      if (!response.ok) {
        const errorData = await response.text();
        console.error(`Upload failed: ${response.status}`, errorData);
        setUploadState("error");
        return;
      }

      const data = await response.json();
      if (data.message === "CV uploaded successfully") {
        setUploadState("success");
      } else {
        setUploadState("error");
      }
    } catch (e) {
      console.error("Upload error:", e);
      setUploadState("error");
    }
  };

  const handleButtonClick = () => {
    fileInputRef.current?.click();
  };

  const fadeIn = {
    hidden: { opacity: 0, y: 10 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.4 } },
  };

  // Don't render anything while checking auth
  if (!user) {
    return null;
  }

  return (
    <div className="min-h-screen bg-background">
      <CandidateNavbar />

      <main className="container mx-auto px-4 py-8">
        <motion.div
          initial="hidden"
          animate="visible"
          variants={fadeIn}
          className="max-w-4xl mx-auto"
        >
          <h1 className="text-3xl font-bold mb-2">Upload Your CV</h1>
          <p className="text-muted-foreground mb-8">
            Upload your CV to apply for jobs and get discovered by employers
          </p>

          <Tabs defaultValue="upload">
            <TabsList className="mb-6">
              <TabsTrigger value="upload">Upload CV</TabsTrigger>
              <TabsTrigger value="create">Create Online CV</TabsTrigger>
              <TabsTrigger value="linkedin">Import from LinkedIn</TabsTrigger>
            </TabsList>

            <TabsContent value="upload">
              <Card>
                <CardHeader>
                  <CardTitle>Upload Your CV</CardTitle>
                  <CardDescription>
                    Upload your CV in PDF, DOCX, or RTF format. Maximum file
                    size: 5MB.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div
                    className={`border-2 border-dashed rounded-lg p-8 text-center ${
                      dragActive
                        ? "border-primary bg-primary/5"
                        : "border-border"
                    } transition-colors`}
                    onDragEnter={handleDrag}
                    onDragLeave={handleDrag}
                    onDragOver={handleDrag}
                    onDrop={handleDrop}
                  >
                    {uploadState === "idle" && (
                      <>
                        <div className="mx-auto w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center mb-4">
                          <Upload className="h-6 w-6 text-primary" />
                        </div>
                        <h3 className="text-lg font-medium mb-2">
                          Drag and drop your CV here
                        </h3>
                        <p className="text-muted-foreground mb-4">
                          or click to browse files
                        </p>
                        <Input
                          type="file"
                          id="cv-upload"
                          ref={fileInputRef}
                          className="hidden"
                          accept=".pdf,.doc,.docx,.rtf"
                          onChange={handleFileInput}
                        />
                        <Button onClick={handleButtonClick}>Select File</Button>
                      </>
                    )}

                    {uploadState === "uploading" && (
                      <div className="space-y-4">
                        <div className="mx-auto w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center">
                          <div className="animate-spin h-6 w-6 border-2 border-primary border-t-transparent rounded-full" />
                        </div>
                        <h3 className="text-lg font-medium">
                          Uploading your CV...
                        </h3>
                        <p className="text-muted-foreground">
                          This will just take a moment
                        </p>
                      </div>
                    )}

                    {uploadState === "success" && (
                      <div className="space-y-4">
                        <div className="mx-auto w-12 h-12 rounded-full bg-green-100 dark:bg-green-900 flex items-center justify-center">
                          <CheckCircle className="h-6 w-6 text-green-600 dark:text-green-400" />
                        </div>
                        <h3 className="text-lg font-medium">
                          Upload Successful!
                        </h3>
                        <p className="text-muted-foreground mb-4">
                          Your CV has been uploaded successfully
                        </p>
                        <div className="flex justify-center gap-4">
                          <Button variant="outline" onClick={() => setShowCV(true)}>View CV</Button>
                          <Button onClick={deleteCV}>Delete CV</Button>  {/* Ajout du bouton de suppression */}
                        </div>
                      </div>
                    )}

                    {uploadState === "error" && (
                      <div className="space-y-4">
                        <div className="mx-auto w-12 h-12 rounded-full bg-red-100 dark:bg-red-900 flex items-center justify-center">
                          <AlertCircle className="h-6 w-6 text-red-600 dark:text-red-400" />
                        </div>
                        <h3 className="text-lg font-medium">Upload Failed</h3>
                        <p className="text-muted-foreground mb-4">
                          There was an error uploading your CV. Please try
                          again.
                        </p>
                        <Button onClick={() => setUploadState("idle")}>
                          Try Again
                        </Button>
                      </div>
                    )}
                  </div>

                  <div className="mt-8 bg-muted p-4 rounded-lg flex gap-3">
                    <Info className="h-5 w-5 text-primary flex-shrink-0 mt-0.5" />
                    <div>
                      <h4 className="font-medium mb-1">CV Tips</h4>
                      <ul className="text-sm text-muted-foreground space-y-1 list-disc pl-4">
                        <li>Keep your CV concise and relevant (1-2 pages)</li>
                        <li>
                          Highlight your achievements with quantifiable results
                        </li>
                        <li>Tailor your CV to the jobs you're applying for</li>
                        <li>Ensure there are no spelling or grammar errors</li>
                      </ul>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="create">
              <Card>
                <CardHeader>
                  <CardTitle>Create Online CV</CardTitle>
                  <CardDescription>
                    Build your CV step by step using our online editor
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="text-center py-12">
                    <FileText className="h-12 w-12 text-primary mx-auto mb-4" />
                    <h3 className="text-lg font-medium mb-2">
                      Create a professional CV online
                    </h3>
                    <p className="text-muted-foreground mb-6 max-w-md mx-auto">
                      Our step-by-step CV builder helps you create a
                      professional CV that stands out to employers
                    </p>
                    <Button>Start Building</Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="linkedin">
              <Card>
                <CardHeader>
                  <CardTitle>Import from LinkedIn</CardTitle>
                  <CardDescription>
                    Import your professional details directly from LinkedIn
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="text-center py-12">
                    <div className="w-12 h-12 rounded-full bg-blue-100 dark:bg-blue-900 flex items-center justify-center mx-auto mb-4">
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        width="24"
                        height="24"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        className="text-blue-600 dark:text-blue-400"
                      >
                        <path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6z"></path>
                        <rect x="2" y="9" width="4" height="12"></rect>
                        <circle cx="4" cy="4" r="2"></circle>
                      </svg>
                    </div>
                    <h3 className="text-lg font-medium mb-2">
                      Connect with LinkedIn
                    </h3>
                    <p className="text-muted-foreground mb-6 max-w-md mx-auto">
                      We'll import your professional experience, skills, and
                      education from your LinkedIn profile
                    </p>

                    <Button className="bg-blue-600 hover:bg-blue-700 text-white">
                      Connect with LinkedIn
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>

          <div className="mt-8">
            <h2 className="text-xl font-bold mb-4">
              What happens after you upload your CV?
            </h2>
            <div className="grid md:grid-cols-3 gap-6">
              <Card>
                <CardContent className="pt-6">
                  <div className="text-center">
                    <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-4">
                      <FileText className="h-5 w-5 text-primary" />
                    </div>
                    <h3 className="font-medium mb-2">AI-Powered Analysis</h3>
                    <p className="text-sm text-muted-foreground">
                      Our AI analyzes your CV and provides insights to help you
                      improve it
                    </p>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="pt-6">
                  <div className="text-center">
                    <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-4">
                      <Search className="h-5 w-5 text-primary" />
                    </div>
                    <h3 className="font-medium mb-2">
                      Discoverable by Employers
                    </h3>
                    <p className="text-sm text-muted-foreground">
                      Employers can find you based on your skills and experience
                    </p>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="pt-6">
                  <div className="text-center">
                    <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-4">
                      <TrendingUp className="h-5 w-5 text-primary" />
                    </div>
                    <h3 className="font-medium mb-2">
                      Personalized Job Matches
                    </h3>
                    <p className="text-sm text-muted-foreground">
                      Get matched with jobs that align with your skills and
                      career goals
                    </p>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </motion.div>
      </main>

      <Modal
        isOpen={showCV}
        onClose={() => setShowCV(false)}
        title="Your CV"
      >
        <div className="w-full h-[80vh]">
          <iframe 
            src="http://localhost:10000/candidate/raw-cv"
            className="w-full h-full border-0"
            title="CV Preview"
          />
        </div>
      </Modal>
    </div>
  );
}
