.class public final Llyiahf/vczjk/y63;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/f43;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/f43;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Llyiahf/vczjk/cf3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/f43;Landroidx/work/impl/WorkDatabase_Impl;Llyiahf/vczjk/o000OO;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/y63;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/y63;->OooOOO:Llyiahf/vczjk/f43;

    iput-object p2, p0, Llyiahf/vczjk/y63;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/y63;->OooOOOo:Llyiahf/vczjk/cf3;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/f43;Llyiahf/vczjk/bf3;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/y63;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/y63;->OooOOO:Llyiahf/vczjk/f43;

    iput-object p2, p0, Llyiahf/vczjk/y63;->OooOOOO:Ljava/lang/Object;

    check-cast p3, Llyiahf/vczjk/eb9;

    iput-object p3, p0, Llyiahf/vczjk/y63;->OooOOOo:Llyiahf/vczjk/cf3;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v1, p0, Llyiahf/vczjk/y63;->OooOOO:Llyiahf/vczjk/f43;

    iget-object v2, p0, Llyiahf/vczjk/y63;->OooOOOO:Ljava/lang/Object;

    iget-object v3, p0, Llyiahf/vczjk/y63;->OooOOOo:Llyiahf/vczjk/cf3;

    iget v4, p0, Llyiahf/vczjk/y63;->OooOOO0:I

    packed-switch v4, :pswitch_data_0

    new-instance v4, Llyiahf/vczjk/y73;

    check-cast v3, Llyiahf/vczjk/o000OO;

    check-cast v2, Landroidx/work/impl/WorkDatabase_Impl;

    invoke-direct {v4, p1, v2, v3}, Llyiahf/vczjk/y73;-><init>(Llyiahf/vczjk/h43;Landroidx/work/impl/WorkDatabase_Impl;Llyiahf/vczjk/o000OO;)V

    invoke-interface {v1, v4, p2}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    move-object v0, p1

    :cond_0
    return-object v0

    :pswitch_0
    check-cast v2, Llyiahf/vczjk/f43;

    const/4 v4, 0x2

    new-array v4, v4, [Llyiahf/vczjk/f43;

    const/4 v5, 0x0

    aput-object v1, v4, v5

    const/4 v1, 0x1

    aput-object v2, v4, v1

    sget-object v1, Llyiahf/vczjk/dk0;->OooOo00:Llyiahf/vczjk/dk0;

    new-instance v2, Llyiahf/vczjk/z63;

    check-cast v3, Llyiahf/vczjk/eb9;

    const/4 v5, 0x0

    invoke-direct {v2, v3, v5}, Llyiahf/vczjk/z63;-><init>(Llyiahf/vczjk/bf3;Llyiahf/vczjk/yo1;)V

    invoke-static {p2, p1, v1, v2, v4}, Llyiahf/vczjk/cp7;->OooOOO(Llyiahf/vczjk/yo1;Llyiahf/vczjk/h43;Llyiahf/vczjk/le3;Llyiahf/vczjk/bf3;[Llyiahf/vczjk/f43;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_1

    move-object v0, p1

    :cond_1
    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
