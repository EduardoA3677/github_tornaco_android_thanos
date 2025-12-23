.class public final Llyiahf/vczjk/qp0;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $id:Ljava/util/UUID;

.field final synthetic $workManagerImpl:Llyiahf/vczjk/oqa;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oqa;Ljava/util/UUID;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qp0;->$workManagerImpl:Llyiahf/vczjk/oqa;

    iput-object p2, p0, Llyiahf/vczjk/qp0;->$id:Ljava/util/UUID;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/qp0;->$workManagerImpl:Llyiahf/vczjk/oqa;

    iget-object v0, v0, Llyiahf/vczjk/oqa;->OooOOO:Landroidx/work/impl/WorkDatabase;

    const-string v1, "workManagerImpl.workDatabase"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/qp0;->$workManagerImpl:Llyiahf/vczjk/oqa;

    iget-object v2, p0, Llyiahf/vczjk/qp0;->$id:Ljava/util/UUID;

    new-instance v3, Llyiahf/vczjk/oO0oO000;

    const/16 v4, 0x14

    invoke-direct {v3, v4, v1, v2}, Llyiahf/vczjk/oO0oO000;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v0, v3}, Llyiahf/vczjk/ru7;->runInTransaction(Ljava/lang/Runnable;)V

    iget-object v0, p0, Llyiahf/vczjk/qp0;->$workManagerImpl:Llyiahf/vczjk/oqa;

    iget-object v1, v0, Llyiahf/vczjk/oqa;->OooOOO0:Llyiahf/vczjk/wh1;

    iget-object v2, v0, Llyiahf/vczjk/oqa;->OooOOO:Landroidx/work/impl/WorkDatabase;

    iget-object v0, v0, Llyiahf/vczjk/oqa;->OooOOOo:Ljava/util/List;

    invoke-static {v1, v2, v0}, Llyiahf/vczjk/t88;->OooO0O0(Llyiahf/vczjk/wh1;Landroidx/work/impl/WorkDatabase;Ljava/util/List;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
