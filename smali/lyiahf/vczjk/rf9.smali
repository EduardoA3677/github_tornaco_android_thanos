.class public final Llyiahf/vczjk/rf9;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $cancelOrReleaseJob:Llyiahf/vczjk/v74;

.field final synthetic $pressScope:Llyiahf/vczjk/o37;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v74;Llyiahf/vczjk/o37;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/rf9;->$cancelOrReleaseJob:Llyiahf/vczjk/v74;

    iput-object p2, p0, Llyiahf/vczjk/rf9;->$pressScope:Llyiahf/vczjk/o37;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/rf9;

    iget-object v0, p0, Llyiahf/vczjk/rf9;->$cancelOrReleaseJob:Llyiahf/vczjk/v74;

    iget-object v1, p0, Llyiahf/vczjk/rf9;->$pressScope:Llyiahf/vczjk/o37;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/rf9;-><init>(Llyiahf/vczjk/v74;Llyiahf/vczjk/o37;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/rf9;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/rf9;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/rf9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/rf9;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/rf9;->$cancelOrReleaseJob:Llyiahf/vczjk/v74;

    iput v3, p0, Llyiahf/vczjk/rf9;->label:I

    invoke-interface {p1, p0}, Llyiahf/vczjk/v74;->Oooooo0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto :goto_1

    :cond_3
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/rf9;->$pressScope:Llyiahf/vczjk/o37;

    iput v2, p0, Llyiahf/vczjk/rf9;->label:I

    invoke-virtual {p1, p0}, Llyiahf/vczjk/o37;->OooO0Oo(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    :goto_1
    return-object v0

    :cond_4
    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
