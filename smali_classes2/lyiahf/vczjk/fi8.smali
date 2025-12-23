.class public final Llyiahf/vczjk/fi8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $enable:Z

.field final synthetic $pref:Llyiahf/vczjk/n17;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/n17;ZLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fi8;->$pref:Llyiahf/vczjk/n17;

    iput-boolean p2, p0, Llyiahf/vczjk/fi8;->$enable:Z

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/fi8;

    iget-object v0, p0, Llyiahf/vczjk/fi8;->$pref:Llyiahf/vczjk/n17;

    iget-boolean v1, p0, Llyiahf/vczjk/fi8;->$enable:Z

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/fi8;-><init>(Llyiahf/vczjk/n17;ZLlyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/fi8;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/fi8;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fi8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/fi8;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/fi8;->$pref:Llyiahf/vczjk/n17;

    iget-boolean v1, p0, Llyiahf/vczjk/fi8;->$enable:Z

    iput v3, p0, Llyiahf/vczjk/fi8;->label:I

    iget-object p1, p1, Llyiahf/vczjk/n17;->OooO00o:Landroid/content/Context;

    invoke-static {p1}, Llyiahf/vczjk/o17;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object p1

    new-instance v3, Llyiahf/vczjk/i17;

    const/4 v4, 0x0

    invoke-direct {v3, v1, v4}, Llyiahf/vczjk/i17;-><init>(ZLlyiahf/vczjk/yo1;)V

    new-instance v1, Llyiahf/vczjk/x27;

    invoke-direct {v1, v3, v4}, Llyiahf/vczjk/x27;-><init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    check-cast p1, Llyiahf/vczjk/c27;

    invoke-virtual {p1, v1, p0}, Llyiahf/vczjk/c27;->OooO00o(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    goto :goto_0

    :cond_2
    move-object p1, v2

    :goto_0
    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    return-object v2
.end method
