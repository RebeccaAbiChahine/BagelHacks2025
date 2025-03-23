"use client"
import { motion } from "framer-motion"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Users, Search, MessageSquare, FileText, PlusCircle } from "lucide-react"
import EmployerNavbar from "@/components/employer-navbar"
import { useState, useEffect } from "react"

export default function EmployerDashboard() {
  const [userInfo, setUserInfo] = useState<{ firstName: string; lastName: string } | null>(null)

  useEffect(() => {
    const fetchUserInfo = async () => {
      try {
        const response = await fetch("http://localhost:10000/api/user-info", {
          credentials: "include",
        })
        if (response.ok) {
          const data = await response.json()
          setUserInfo(data)
        }
      } catch (error) {
        console.error("Failed to fetch user info:", error)
      }
    }

    fetchUserInfo()
  }, [])

  const fadeIn = {
    hidden: { opacity: 0, y: 10 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.4 } },
  }

  const welcomeTextFade = {
    hidden: { opacity: 0 },
    visible: { opacity: 1, transition: { duration: 0.5, delay: 0.2 } }
  };

  return (
    <div className="min-h-screen bg-background">
      <EmployerNavbar />

      <main className="container mx-auto px-4 py-8">
        <motion.div
          initial="hidden"
          animate="visible"
          variants={fadeIn}
          className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8"
        >
          <div>
            <motion.h1 
              className="text-3xl font-bold mb-4"
              initial="hidden"
              animate="visible"
              variants={welcomeTextFade}
            >
              Welcome back{userInfo ? `, ${userInfo.firstName}` : ''}
            </motion.h1>
            <p className="text-muted-foreground">Manage your recruitment process</p>
          </div>
          <div className="mt-4 md:mt-0 flex gap-3">
            <Button
              variant="outline"
              className="gap-2"
              onClick={() => (window.location.href = "/employer/search-candidates")}
            >
              <Search size={16} /> Search Candidates
            </Button>
            <Button className="gap-2" onClick={() => (window.location.href = "/employer/post-job")}>
              <PlusCircle size={16} /> Post New Job
            </Button>
          </div>
        </motion.div>

        <motion.div
          initial="hidden"
          animate="visible"
          variants={fadeIn}
          className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8"
        >
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-lg flex items-center gap-2">
                <FileText size={18} className="text-primary" /> Active Job Postings
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-3xl font-bold">5</span>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8"
                    onClick={() => (window.location.href = "/employer/jobs")}
                  >
                    Manage
                  </Button>
                </div>
                <p className="text-sm text-muted-foreground">You have 5 active job postings receiving applications</p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-lg flex items-center gap-2">
                <Users size={18} className="text-primary" /> Candidate Applications
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-3xl font-bold">28</span>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8"
                    onClick={() => (window.location.href = "/employer/applications")}
                  >
                    Review
                  </Button>
                </div>
                <p className="text-sm text-muted-foreground">You have 12 new applications to review</p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-lg flex items-center gap-2">
                <MessageSquare size={18} className="text-primary" /> Messages
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-3xl font-bold">7</span>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8"
                    onClick={() => (window.location.href = "/communication")}
                  >
                    Open Inbox
                  </Button>
                </div>
                <p className="text-sm text-muted-foreground">You have 7 unread messages from candidates</p>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div initial="hidden" animate="visible" variants={fadeIn} className="mb-8">
          <Tabs defaultValue="applications">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-2xl font-bold">Recruitment Pipeline</h2>
              <TabsList>
                <TabsTrigger value="applications">Applications</TabsTrigger>
                <TabsTrigger value="interviews">Interviews</TabsTrigger>
                <TabsTrigger value="offers">Offers</TabsTrigger>
              </TabsList>
            </div>

            <TabsContent value="applications" className="mt-0">
              <Card>
                <CardContent className="p-6">
                  <div className="space-y-4">
                    {[1, 2, 3].map((application) => (
                      <div
                        key={application}
                        className="flex items-center justify-between p-4 border border-border rounded-lg"
                      >
                        <div className="flex items-center gap-4">
                          <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                            <Users size={20} className="text-primary" />
                          </div>
                          <div>
                            <h3 className="font-medium">Sarah Johnson</h3>
                            <p className="text-sm text-muted-foreground">Applied for: Senior Frontend Developer</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Button size="sm" variant="outline">
                            View CV
                          </Button>
                          <Button size="sm">Review</Button>
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="mt-4 text-center">
                    <Button variant="link">View All Applications</Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="interviews" className="mt-0">
              <Card>
                <CardContent className="p-6">
                  <div className="space-y-4">
                    {[1, 2].map((interview) => (
                      <div
                        key={interview}
                        className="flex items-center justify-between p-4 border border-border rounded-lg"
                      >
                        <div className="flex items-center gap-4">
                          <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                            <Users size={20} className="text-primary" />
                          </div>
                          <div>
                            <h3 className="font-medium">Michael Chen</h3>
                            <p className="text-sm text-muted-foreground">Interview for: UX Designer</p>
                            <p className="text-xs text-primary">Scheduled: Tomorrow, 2:00 PM</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Button size="sm" variant="outline">
                            Reschedule
                          </Button>
                          <Button size="sm">Join Call</Button>
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="mt-4 text-center">
                    <Button variant="link">View All Interviews</Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="offers" className="mt-0">
              <Card>
                <CardContent className="p-6">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between p-4 border border-border rounded-lg">
                      <div className="flex items-center gap-4">
                        <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                          <Users size={20} className="text-primary" />
                        </div>
                        <div>
                          <h3 className="font-medium">Jessica Williams</h3>
                          <p className="text-sm text-muted-foreground">Offer for: Product Manager</p>
                          <p className="text-xs text-amber-600">Pending Response</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Button size="sm" variant="outline">
                          View Details
                        </Button>
                        <Button size="sm">Follow Up</Button>
                      </div>
                    </div>
                  </div>
                  <div className="mt-4 text-center">
                    <Button variant="link">View All Offers</Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </motion.div>

        <motion.div
          initial="hidden"
          animate="visible"
          variants={fadeIn}
          className="grid grid-cols-1 md:grid-cols-2 gap-6"
        >
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Search size={20} className="text-primary" />
                Candidate Search
              </CardTitle>
              <CardDescription>Find candidates based on skills and experience</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-3">
                  <div className="bg-muted p-3 rounded-lg text-center cursor-pointer hover:bg-muted/80 transition-colors">
                    <p className="text-sm font-medium">Frontend Development</p>
                    <p className="text-xs text-muted-foreground">124 candidates</p>
                  </div>
                  <div className="bg-muted p-3 rounded-lg text-center cursor-pointer hover:bg-muted/80 transition-colors">
                    <p className="text-sm font-medium">UX/UI Design</p>
                    <p className="text-xs text-muted-foreground">87 candidates</p>
                  </div>
                  <div className="bg-muted p-3 rounded-lg text-center cursor-pointer hover:bg-muted/80 transition-colors">
                    <p className="text-sm font-medium">Product Management</p>
                    <p className="text-xs text-muted-foreground">56 candidates</p>
                  </div>
                  <div className="bg-muted p-3 rounded-lg text-center cursor-pointer hover:bg-muted/80 transition-colors">
                    <p className="text-sm font-medium">Data Science</p>
                    <p className="text-xs text-muted-foreground">92 candidates</p>
                  </div>
                </div>
                <Button className="w-full" onClick={() => (window.location.href = "/employer/search-candidates")}>
                  Advanced Search
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText size={20} className="text-primary" />
                Feedback Analytics
              </CardTitle>
              <CardDescription>Insights from candidate feedback</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-3">
                  <div className="bg-muted p-3 rounded-lg text-center">
                    <p className="text-2xl font-bold">85%</p>
                    <p className="text-xs text-muted-foreground">Positive Feedback</p>
                  </div>
                  <div className="bg-muted p-3 rounded-lg text-center">
                    <p className="text-2xl font-bold">42</p>
                    <p className="text-xs text-muted-foreground">Feedback Given</p>
                  </div>
                  <div className="bg-muted p-3 rounded-lg text-center">
                    <p className="text-2xl font-bold">$180</p>
                    <p className="text-xs text-muted-foreground">Rebates Earned</p>
                  </div>
                </div>
                <div className="bg-muted p-4 rounded-lg">
                  <h3 className="text-sm font-medium mb-2">Top Feedback Categories</h3>
                  <ul className="space-y-2 text-sm">
                    <li className="flex justify-between">
                      <span>Interview Process</span>
                      <span className="font-medium">32%</span>
                    </li>
                    <li className="flex justify-between">
                      <span>CV Improvement</span>
                      <span className="font-medium">28%</span>
                    </li>
                    <li className="flex justify-between">
                      <span>Technical Skills</span>
                      <span className="font-medium">24%</span>
                    </li>
                  </ul>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </main>
    </div>
  )
}

