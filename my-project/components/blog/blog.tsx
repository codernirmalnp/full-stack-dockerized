import React from 'react'
import Image from 'next/image'
export const Blog = () => {
    return (
        <>
            {/* Blog Section for main*/}
            < section id="blog" className="bg-white dark:bg-darkBlue" >
                {/* Blog Container*/}
                < div
                    className="container flex flex-col items-center mx-auto px-6 pt-24 pb-32 md:flex-row md:space-x-16"
                >
                    {/* Image*/}
                    < div className=" relative md:w-1/2 w-96 h-[30rem] mb-7" >
                        <Image
                            src="/runon.png"
                            alt=""
                            fill
                            className="mb-10 "
                        />
                    </div >
                    {/* Content*/}
                    < div className="flex flex-col items-start md:w-1/2 self-start" >
                        <div className="flex flex-col space-y-5">
                            <h4 className="max-w-lg text-xl font-bold md:text-4xl">
                                Creating Best Version of OneSelf
                            </h4>
                            <p className="text-md max-w-lg text-justify md:text-lg">
                                In my best version of myself, I am confident and authentic, unafraid to speak my truth and pursue my passions. I prioritize my physical and mental health, maintaining a balanced lifestyle and taking care of my well-being. I am compassionate and empathetic, treating others with kindness and respect. I am curious and open-minded, always seeking new
                                knowledge and experiences to broaden my perspective.
                            </p>
                            <p className="text-md max-w-lg text-justify md:text-lg">
                                I am resilient and adaptable, able to navigate challenges with grace and determination. I am a good listener and communicator, fostering meaningful connections with those around me. And I am grateful for the abundance in my life, cherishing each moment and spreading positivity wherever I go.
                            </p>

                        </div>

                        {/* Link*/}
                        <div className="block mt-4">
                            <a href="#" className="border-b text-center text-md border-accentCyan text-accentCyan">
                                Read More Blogs
                                
                            </a>
                            
                        </div>
                    </div >
                </div >
            </section >
        </>
    )
}
