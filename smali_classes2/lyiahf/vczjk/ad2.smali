.class public final Llyiahf/vczjk/ad2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/hl7;

.field public final synthetic OooOOO0:Llyiahf/vczjk/bd2;

.field public final synthetic OooOOOO:Llyiahf/vczjk/h43;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bd2;Llyiahf/vczjk/hl7;Llyiahf/vczjk/h43;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ad2;->OooOOO0:Llyiahf/vczjk/bd2;

    iput-object p2, p0, Llyiahf/vczjk/ad2;->OooOOO:Llyiahf/vczjk/hl7;

    iput-object p3, p0, Llyiahf/vczjk/ad2;->OooOOOO:Llyiahf/vczjk/h43;

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 7

    instance-of v0, p2, Llyiahf/vczjk/zc2;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/zc2;

    iget v1, v0, Llyiahf/vczjk/zc2;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/zc2;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/zc2;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/zc2;-><init>(Llyiahf/vczjk/ad2;Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/zc2;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/zc2;->label:I

    sget-object v3, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v4, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v4, :cond_1

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v3

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p2, p0, Llyiahf/vczjk/ad2;->OooOOO0:Llyiahf/vczjk/bd2;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, p0, Llyiahf/vczjk/ad2;->OooOOO:Llyiahf/vczjk/hl7;

    iget-object v5, v2, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    sget-object v6, Llyiahf/vczjk/bua;->OooO0Oo:Llyiahf/vczjk/h87;

    if-eq v5, v6, :cond_3

    iget-object p2, p2, Llyiahf/vczjk/bd2;->OooOOO:Llyiahf/vczjk/ze3;

    invoke-interface {p2, v5, p1}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/Boolean;

    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p2

    if-nez p2, :cond_4

    :cond_3
    iput-object p1, v2, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/zc2;->label:I

    iget-object p2, p0, Llyiahf/vczjk/ad2;->OooOOOO:Llyiahf/vczjk/h43;

    invoke-interface {p2, p1, v0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_4

    return-object v1

    :cond_4
    return-object v3
.end method
