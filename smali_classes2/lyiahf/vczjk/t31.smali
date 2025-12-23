.class public final Llyiahf/vczjk/t31;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO:I

.field public final synthetic OooOOO0:Llyiahf/vczjk/rs0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/rs0;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/t31;->OooOOO0:Llyiahf/vczjk/rs0;

    iput p2, p0, Llyiahf/vczjk/t31;->OooOOO:I

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 5

    instance-of v0, p2, Llyiahf/vczjk/s31;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/s31;

    iget v1, v0, Llyiahf/vczjk/s31;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/s31;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/s31;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/s31;-><init>(Llyiahf/vczjk/t31;Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/s31;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/s31;->label:I

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v2, :cond_3

    if-eq v2, v4, :cond_2

    if-ne v2, v3, :cond_1

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_3

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_3
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    new-instance p2, Llyiahf/vczjk/kx3;

    iget v2, p0, Llyiahf/vczjk/t31;->OooOOO:I

    invoke-direct {p2, v2, p1}, Llyiahf/vczjk/kx3;-><init>(ILjava/lang/Object;)V

    iput v4, v0, Llyiahf/vczjk/s31;->label:I

    iget-object p1, p0, Llyiahf/vczjk/t31;->OooOOO0:Llyiahf/vczjk/rs0;

    invoke-interface {p1, p2, v0}, Llyiahf/vczjk/if8;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_4

    goto :goto_2

    :cond_4
    :goto_1
    iput v3, v0, Llyiahf/vczjk/s31;->label:I

    invoke-static {v0}, Llyiahf/vczjk/ls6;->OooOOoo(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_5

    :goto_2
    return-object v1

    :cond_5
    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
