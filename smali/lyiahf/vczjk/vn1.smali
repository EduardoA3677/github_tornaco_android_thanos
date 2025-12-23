.class public final Llyiahf/vczjk/vn1;
.super Llyiahf/vczjk/rs7;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $onDown:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)V
    .locals 0

    iput-object p2, p0, Llyiahf/vczjk/vn1;->$onDown:Llyiahf/vczjk/oe3;

    invoke-direct {p0, p1}, Llyiahf/vczjk/rs7;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/vn1;

    iget-object v1, p0, Llyiahf/vczjk/vn1;->$onDown:Llyiahf/vczjk/oe3;

    invoke-direct {v0, p2, v1}, Llyiahf/vczjk/vn1;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)V

    iput-object p1, v0, Llyiahf/vczjk/vn1;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/kb9;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/vn1;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/vn1;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/vn1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/vn1;->label:I

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
    iget-object v1, p0, Llyiahf/vczjk/vn1;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/kb9;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/vn1;->L$0:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/kb9;

    iput-object v1, p0, Llyiahf/vczjk/vn1;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/vn1;->label:I

    invoke-static {v1, p0}, Llyiahf/vczjk/ng0;->OooO0Oo(Llyiahf/vczjk/kb9;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto :goto_1

    :cond_3
    :goto_0
    check-cast p1, Llyiahf/vczjk/ky6;

    invoke-virtual {p1}, Llyiahf/vczjk/ky6;->OooO00o()V

    iget-object v3, p0, Llyiahf/vczjk/vn1;->$onDown:Llyiahf/vczjk/oe3;

    new-instance v4, Llyiahf/vczjk/p86;

    iget-wide v5, p1, Llyiahf/vczjk/ky6;->OooO0OO:J

    invoke-direct {v4, v5, v6}, Llyiahf/vczjk/p86;-><init>(J)V

    invoke-interface {v3, v4}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/vn1;->L$0:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/vn1;->label:I

    sget-object p1, Llyiahf/vczjk/dg9;->OooO00o:Llyiahf/vczjk/df9;

    sget-object p1, Llyiahf/vczjk/fy6;->OooOOO:Llyiahf/vczjk/fy6;

    invoke-static {v1, p1, p0}, Llyiahf/vczjk/dg9;->OooO0oO(Llyiahf/vczjk/kb9;Llyiahf/vczjk/fy6;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    :goto_1
    return-object v0

    :cond_4
    :goto_2
    check-cast p1, Llyiahf/vczjk/ky6;

    if-eqz p1, :cond_5

    invoke-virtual {p1}, Llyiahf/vczjk/ky6;->OooO00o()V

    :cond_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
