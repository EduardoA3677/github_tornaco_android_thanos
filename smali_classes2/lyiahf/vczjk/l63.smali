.class public final Llyiahf/vczjk/l63;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/hl7;

.field public final synthetic OooOOO0:Llyiahf/vczjk/eb9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/hl7;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    check-cast p1, Llyiahf/vczjk/eb9;

    iput-object p1, p0, Llyiahf/vczjk/l63;->OooOOO0:Llyiahf/vczjk/eb9;

    iput-object p2, p0, Llyiahf/vczjk/l63;->OooOOO:Llyiahf/vczjk/hl7;

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 4

    instance-of v0, p2, Llyiahf/vczjk/k63;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/k63;

    iget v1, v0, Llyiahf/vczjk/k63;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/k63;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/k63;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/k63;-><init>(Llyiahf/vczjk/l63;Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/k63;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/k63;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/k63;->L$1:Ljava/lang/Object;

    iget-object v0, v0, Llyiahf/vczjk/k63;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/l63;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iput-object p0, v0, Llyiahf/vczjk/k63;->L$0:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/k63;->L$1:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/k63;->label:I

    iget-object p2, p0, Llyiahf/vczjk/l63;->OooOOO0:Llyiahf/vczjk/eb9;

    invoke-interface {p2, p1, v0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    if-ne p2, v1, :cond_3

    return-object v1

    :cond_3
    move-object v0, p0

    :goto_1
    check-cast p2, Ljava/lang/Boolean;

    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p2

    if-nez p2, :cond_4

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_4
    iget-object p2, v0, Llyiahf/vczjk/l63;->OooOOO:Llyiahf/vczjk/hl7;

    iput-object p1, p2, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    new-instance p1, Llyiahf/vczjk/o000oOoO;

    invoke-direct {p1, v0}, Llyiahf/vczjk/o000oOoO;-><init>(Llyiahf/vczjk/h43;)V

    throw p1
.end method
