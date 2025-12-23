.class public final Llyiahf/vczjk/e17;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $backCallBack:Llyiahf/vczjk/d17;

.field final synthetic $enabled:Z

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/d17;ZLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/e17;->$backCallBack:Llyiahf/vczjk/d17;

    iput-boolean p2, p0, Llyiahf/vczjk/e17;->$enabled:Z

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/e17;

    iget-object v0, p0, Llyiahf/vczjk/e17;->$backCallBack:Llyiahf/vczjk/d17;

    iget-boolean v1, p0, Llyiahf/vczjk/e17;->$enabled:Z

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/e17;-><init>(Llyiahf/vczjk/d17;ZLlyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/e17;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/e17;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/e17;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/e17;->label:I

    if-nez v0, :cond_2

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/e17;->$backCallBack:Llyiahf/vczjk/d17;

    iget-boolean v0, p0, Llyiahf/vczjk/e17;->$enabled:Z

    if-nez v0, :cond_0

    iget-boolean v1, p1, Llyiahf/vczjk/d17;->OooO0oO:Z

    if-nez v1, :cond_0

    iget-boolean v1, p1, Llyiahf/vczjk/y96;->OooO00o:Z

    if-eqz v1, :cond_0

    iget-object v1, p1, Llyiahf/vczjk/d17;->OooO0o:Llyiahf/vczjk/x96;

    if-eqz v1, :cond_0

    invoke-virtual {v1}, Llyiahf/vczjk/x96;->OooO00o()V

    :cond_0
    iput-boolean v0, p1, Llyiahf/vczjk/y96;->OooO00o:Z

    iget-object p1, p1, Llyiahf/vczjk/y96;->OooO0OO:Llyiahf/vczjk/wf3;

    if-eqz p1, :cond_1

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
