import React from 'react'
import { DashboardLayout } from '../../components/dashboard'
import Breadcrumb from '../../components/reuseable/breadcrumb'
import BreadcrumbItem from '../../components/reuseable/breadcrumbItem'

import { TableDescription } from '../../components/reuseable/TableDescription'

const Users = () => {
    return (
        <DashboardLayout>
            <Breadcrumb>
                <BreadcrumbItem href="/admin">Home</BreadcrumbItem>
            </Breadcrumb>
            <TableDescription title="Users"></TableDescription>


        </DashboardLayout >
    )
}
export default Users;
