import React from 'react'
import Image from 'next/image'
export const Testimonials = () => {
    return (
        <section id="testimonials" className="bg-gray-50 dark:bg-darkBlue">
            {/* Testimonials Container*/}
            <div className="container mx-auto px-6 pt-12 pb-80 md:pb-96">
                {/* Boxes Container*/}
                <div
                    className="flex flex-col w-full space-y-6 md:flex-row md:space-y-0 md:space-x-12"
                >

                    {/* Box 1*/}
                    <div
                        className="flex flex-col p-10 space-y-6 rounded-lg bg-gray-100 dark:bg-darkBlue3 md:w-1/3"
                    >
                        <p className="text-sm leading-5 md:text-lg text-justify">
                            Nirmal Dangi is an exceptional software developer with a deep understanding of programming languages, frameworks, and database systems.
                        </p>
                        {/* Developer Info*/}
                        <div className="flex space-x-4 items-center">
                            <div className='relative w-16 h-16'>
                                <Image
                                    src="/amit.jpeg"
                                    alt=""
                                    fill
                                    className=" rounded-full"
                                />
                            </div>

                            <div>
                                <h5 className="text-md font-semibold">Amit Rajbhandari</h5>
                                <p className="text-sm font-extralight">
                                    Front End Developer
                                </p>
                            </div>
                        </div>
                    </div>

                    {/* Box 2*/}
                    <div
                        className="flex flex-col p-10 space-y-6 rounded-lg bg-gray-100 dark:bg-darkBlue3 md:w-1/3"
                    >
                        <p className="text-sm leading-5 md:text-lg text-justify">

                            Nirmal Dangi is also an excellent team player, always willing to lend a helping hand and collaborate with their colleagues to deliver the best possible results.
                        </p>
                        {/* Developer Info*/}
                        <div className="flex space-x-4 items-center">
                            <div className='relative w-16 h-16'>
                                <Image
                                    src="/hari.jpeg"
                                    alt=""
                                    fill
                                    className=" rounded-full"
                                />
                            </div>
                            <div>
                                <h5 className="text-md font-semibold">Hari Shreshta </h5>
                                <p className="text-sm font-extralight">Full-stack Developer at Resimator Oy</p>
                            </div>
                        </div>
                    </div>

                    {/* Box 3*/}
                    <div
                        className="flex flex-col p-10 space-y-6 rounded-lg bg-gray-100 dark:bg-darkBlue3 md:w-1/3"
                    >
                        <p className="text-sm leading-5 md:text-lg">
                            I highly recommend Nirmal Dangi for any software development role and am confident that they will make a valuable contribution to any organization.
                        </p>
                        {/* Developer Info*/}
                        <div className="flex space-x-4 items-center">
                            <div className='relative w-16 h-16'>
                                <Image
                                    src="/anlisha.jpeg"
                                    alt=""
                                    fill
                                    className=" rounded-full"
                                />
                            </div>

                            <div>
                                <h5 className="text-md font-semibold">Anlisha Maharjan</h5>
                                <p className="text-sm font-extralight">Full Stack Engineer</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

    )
}
