.class public final Llyiahf/vczjk/ct0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/xr1;

.field public final synthetic OooOOO0:Llyiahf/vczjk/hl7;

.field public final synthetic OooOOOO:Llyiahf/vczjk/et0;

.field public final synthetic OooOOOo:Llyiahf/vczjk/h43;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hl7;Llyiahf/vczjk/xr1;Llyiahf/vczjk/et0;Llyiahf/vczjk/h43;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ct0;->OooOOO0:Llyiahf/vczjk/hl7;

    iput-object p2, p0, Llyiahf/vczjk/ct0;->OooOOO:Llyiahf/vczjk/xr1;

    iput-object p3, p0, Llyiahf/vczjk/ct0;->OooOOOO:Llyiahf/vczjk/et0;

    iput-object p4, p0, Llyiahf/vczjk/ct0;->OooOOOo:Llyiahf/vczjk/h43;

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 7

    instance-of v0, p2, Llyiahf/vczjk/bt0;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/bt0;

    iget v1, v0, Llyiahf/vczjk/bt0;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/bt0;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/bt0;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/bt0;-><init>(Llyiahf/vczjk/ct0;Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/bt0;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/bt0;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/bt0;->L$2:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/v74;

    iget-object p1, v0, Llyiahf/vczjk/bt0;->L$1:Ljava/lang/Object;

    iget-object v0, v0, Llyiahf/vczjk/bt0;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ct0;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p2, p0, Llyiahf/vczjk/ct0;->OooOOO0:Llyiahf/vczjk/hl7;

    iget-object p2, p2, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/v74;

    if-eqz p2, :cond_3

    new-instance v2, Llyiahf/vczjk/mv0;

    const-string v4, "Child of the scoped flow was cancelled"

    invoke-direct {v2, v4}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    invoke-interface {p2, v2}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    iput-object p0, v0, Llyiahf/vczjk/bt0;->L$0:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/bt0;->L$1:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/bt0;->L$2:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/bt0;->label:I

    invoke-interface {p2, v0}, Llyiahf/vczjk/v74;->Oooooo0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p2

    if-ne p2, v1, :cond_3

    return-object v1

    :cond_3
    move-object v0, p0

    :goto_1
    iget-object p2, v0, Llyiahf/vczjk/ct0;->OooOOO0:Llyiahf/vczjk/hl7;

    sget-object v1, Llyiahf/vczjk/as1;->OooOOOo:Llyiahf/vczjk/as1;

    new-instance v2, Llyiahf/vczjk/at0;

    iget-object v4, v0, Llyiahf/vczjk/ct0;->OooOOOo:Llyiahf/vczjk/h43;

    iget-object v5, v0, Llyiahf/vczjk/ct0;->OooOOOO:Llyiahf/vczjk/et0;

    const/4 v6, 0x0

    invoke-direct {v2, v5, v4, p1, v6}, Llyiahf/vczjk/at0;-><init>(Llyiahf/vczjk/et0;Llyiahf/vczjk/h43;Ljava/lang/Object;Llyiahf/vczjk/yo1;)V

    iget-object p1, v0, Llyiahf/vczjk/ct0;->OooOOO:Llyiahf/vczjk/xr1;

    invoke-static {p1, v6, v1, v2, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object p1

    iput-object p1, p2, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
