.class public final Llyiahf/vczjk/z95;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $lifecycle:Llyiahf/vczjk/ky4;

.field final synthetic $mainVM:Llyiahf/vczjk/ua5;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ua5;Llyiahf/vczjk/ky4;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/z95;->$mainVM:Llyiahf/vczjk/ua5;

    iput-object p2, p0, Llyiahf/vczjk/z95;->$lifecycle:Llyiahf/vczjk/ky4;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/z95;

    iget-object v0, p0, Llyiahf/vczjk/z95;->$mainVM:Llyiahf/vczjk/ua5;

    iget-object v1, p0, Llyiahf/vczjk/z95;->$lifecycle:Llyiahf/vczjk/ky4;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/z95;-><init>(Llyiahf/vczjk/ua5;Llyiahf/vczjk/ky4;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/z95;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/z95;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/z95;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/z95;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/z95;->$mainVM:Llyiahf/vczjk/ua5;

    iget-object v0, p0, Llyiahf/vczjk/z95;->$lifecycle:Llyiahf/vczjk/ky4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/fy4;->OooO0o0(Llyiahf/vczjk/ky4;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
