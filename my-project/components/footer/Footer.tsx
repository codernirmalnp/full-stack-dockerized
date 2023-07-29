import React from 'react'
import Image from 'next/image'
export const Footer = () => {
    return (
        <>

            <footer className="bg-darkBlue2 text-white">
                <div className="container mx-auto pt-12 px-5 pb-10">
                    {/* Flex Container For All Items*/}
                    <div
                        className="flex flex-col justify-between space-y-24 md:flex-row md:space-y-0"
                    >
                        {/* Email & Phone*/}
                        <div className="mt-10 space-y-6">
                            <div className="flex items-center space-x-3 md:-mt-10">
                                <div className="relative w-6 h-6 scale-10">
                                    <Image fill src="/icon-phone.svg" alt="" className="" />
                                </div>
                                <div>+61450-685-517</div>
                            </div>
                            <div className="flex items-center space-x-3">
                                <div className="relative w-6 h-6 scale-10">
                                    <Image fill src="/icon-email.svg" alt="" className="" />
                                </div>
                                <div>codernirmal@gmail.com</div>
                            </div>
                        </div>



                        {/* Social*/}
                        <div className="flex justify-center pb-10 space-x-3">
                            <div>
                                <a href="#">
                                    <div className='relative p-2 h-7 w-7 bg-darkBlue rounded-full ficon'>
                                        <Image
                                            src="/github.svg"
                                            alt=""
                                            fill
                                            className=""
                                        />
                                    </div>
                                </a>
                            </div>
                            <div>
                                <a href="#">
                                    <div className='relative  h-6 w-6 p-2 bg-darkBlue rounded-full ficon'>
                                        <Image
                                            src="/facebook.svg"
                                            alt=""
                                            fill

                                        />
                                    </div>
                                </a>
                            </div>
                            <div>
                                <a href="#">
                                    <div className='relative p-2 h-6 w-6 bg-darkBlue rounded-full ficon'>
                                        <Image
                                            fill
                                            src="/twitter.svg"
                                            alt=""
                                           
                                        />
                                    </div>
                                </a>
                            </div>
                            <div>
                                <a href="#">
                                    <div className='relative p-2 h-6 w-6 bg-darkBlue rounded-full ficon'>
                                        <Image
                                            fill
                                            src="/instagram.svg"
                                            alt=""
                                          
                                        />
                                    </div>

                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </footer>
        </>
    )
}
