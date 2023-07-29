import React, { useState } from 'react'
import Breadcrumb from '../../components/reuseable/breadcrumb'
import BreadcrumbItem from '../../components/reuseable/breadcrumbItem'
import { DashboardLayout } from '../../components/dashboard';



const Index = () => {

   return (

      <DashboardLayout>
         <Breadcrumb>
            <BreadcrumbItem href="/admin">Home</BreadcrumbItem>
         </Breadcrumb>
         


      </DashboardLayout >



   );





}

export default Index;