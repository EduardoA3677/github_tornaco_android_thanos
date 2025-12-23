.class public final Llyiahf/vczjk/fo3;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/cp6;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/sb0;


# virtual methods
.method public final OooooOo(Llyiahf/vczjk/f62;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    instance-of p1, p2, Llyiahf/vczjk/ew7;

    if-eqz p1, :cond_0

    check-cast p2, Llyiahf/vczjk/ew7;

    goto :goto_0

    :cond_0
    const/4 p2, 0x0

    :goto_0
    if-nez p2, :cond_1

    new-instance p2, Llyiahf/vczjk/ew7;

    invoke-direct {p2}, Llyiahf/vczjk/ew7;-><init>()V

    :cond_1
    iget-object p1, p0, Llyiahf/vczjk/fo3;->OooOoOO:Llyiahf/vczjk/sb0;

    new-instance v0, Llyiahf/vczjk/ts1;

    invoke-direct {v0, p1}, Llyiahf/vczjk/ts1;-><init>(Llyiahf/vczjk/sb0;)V

    iput-object v0, p2, Llyiahf/vczjk/ew7;->OooO0OO:Llyiahf/vczjk/mc4;

    return-object p2
.end method
