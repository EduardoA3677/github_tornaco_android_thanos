.class public abstract Llyiahf/vczjk/p52;
.super Llyiahf/vczjk/o52;
.source "SourceFile"


# instance fields
.field public final OooOOO:Llyiahf/vczjk/dp8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dp8;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/p52;->OooOOO:Llyiahf/vczjk/dp8;

    return-void
.end method


# virtual methods
.method public final o00000oO(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;
    .locals 1

    const-string v0, "newAttributes"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/o52;->o0OOO0o()Llyiahf/vczjk/d3a;

    move-result-object v0

    if-eq p1, v0, :cond_0

    new-instance v0, Llyiahf/vczjk/hp8;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/hp8;-><init>(Llyiahf/vczjk/dp8;Llyiahf/vczjk/d3a;)V

    return-object v0

    :cond_0
    return-object p0
.end method

.method public final o00000oo()Llyiahf/vczjk/dp8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/p52;->OooOOO:Llyiahf/vczjk/dp8;

    return-object v0
.end method

.method public final o0000Ooo(Z)Llyiahf/vczjk/dp8;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/o52;->o000000o()Z

    move-result v0

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/p52;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/dp8;->o0000Ooo(Z)Llyiahf/vczjk/dp8;

    move-result-object p1

    invoke-virtual {p0}, Llyiahf/vczjk/o52;->o0OOO0o()Llyiahf/vczjk/d3a;

    move-result-object v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/dp8;->o00000oO(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;

    move-result-object p1

    return-object p1
.end method
