import React from 'react'
import { Early } from '../svg/early'
import { Apply } from '../svg/apply'
import { Try } from '../svg/try'

export const Experience = () => {
  return (
    <section id="features" className='pt-12 bg-gray-50 dark:bg-darkBlue1'>
      <div className="relative container flex flex-col items-start px-6 pb-32 pt-20 mx-auto md:flex-row md:space-x-7 space-y-12">
        {/*Horizontal Line*/}
        <div className="hidden absolute top-40 w-10/12 left-16 h-3 bg-cyan-500 md:block" />
        <div className="absolute w-2 left-1/2 h-2/3 -ml-1 bg-cyan-500 md:hidden" />
        <div className="relative flex flex-col p-6 space-y-6 bg-white rounded-lg md:w-1/3" >
          {/*  Image Positioning  */}
          <div className="absolute -ml-10 left-1/2 -top-10 md:left-16">
            {/* Image Container For Background & Center */}
            <div
              className="flex items-center justify-center w-20 h-20 p-4 rounded-full  dark:bg-gray-700"
            >
              <Early />
            </div>
          </div>
          <h5
            className="pt-7 text-xl font-bold text-center capitalize md:text-left"
          >
            Early Development
          </h5>
          <p className="text-justify text-gray-400 ">
            I have had studied Nine-Twelve Computer Engineering Where I had learned
            multiple Technologies of the Coding including HTML , CSS  , JS , PHP , .NET and Java . Along
            with that I developed CMS News Portal Using HTML,CSS and jquery and
            Popular PHP framework Laravel. First Time I started coding when I was just
            13. I feel fasniting and enthuquestic in tech up till now.
          </p>
        </div>
        <div className="relative flex flex-col p-6 space-y-6 bg-white rounded-lg  md:w-1/3 " >
          {/*  Image Positioning  */}
          <div className="absolute -ml-10 left-1/2 -top-10 md:left-16 ">
            {/* Image Container For Background & Center */}
            <div
              className="flex items-center justify-center w-20 h-20 p-4 rounded-full dark:bg-gray-700"
            >
              <Apply />
            </div>
          </div>
          <h5
            className="pt-4 text-xl font-bold text-center capitalize md:text-left"
          >
            Applied in Real Field
          </h5>
          <p className="text-justify max-w-md text-gray-400 ">
            After graduatin High School  I applied to many tech jobs in Nepal.I made a breakthrough out there
            by gettin job at Resimator.io which is specialized in Developing of Modern Web Application for Poland Business.
            Allover Mine major contribution at that comapany was  developing web Application like kiosk and investor portal
             for buinesses using React ,Next JS and implemened Libary and UI.
           

          </p>
        </div>
        <div className="relative flex flex-col p-6 space-y-6 bg-white rounded-lg   md:w-1/3 " >
          {/*  Image Positioning  */}
          <div className="absolute -ml-10 left-1/2 -top-10 md:left-16 ">
            {/* Image Container For Background & Center */}
            <div
              className="flex items-center justify-center w-20 h-20 p-4 rounded-full dark:bg-gray-700"
            >
              <Try />
            </div>
          </div>
          <h5
            className="pt-4 text-xl font-bold text-center capitalize md:text-left"
          >
            Pursing and Lokin For
          </h5>
          <p className=" text-gray-400 text-justify">
            Currently Here in Australia I am pursuing Bachelor in Software Development in Melbourne Institute
            of technology. I am enjoyin  my days all out here and studyin with casual jobs. MoreEver I  Really feel
            overwhelmed by not implementing my skills in real life . I just really love to code and spend days and
            nights to fix bugs.
          </p>
        </div>


      </div>

    </section>
  )
}
