.class public abstract Llyiahf/vczjk/k23;
.super Llyiahf/vczjk/iaa;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/yk4;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/dp8;

.field public final OooOOOO:Llyiahf/vczjk/dp8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)V
    .locals 1

    const-string v0, "lowerBound"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "upperBound"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/k23;->OooOOO:Llyiahf/vczjk/dp8;

    iput-object p2, p0, Llyiahf/vczjk/k23;->OooOOOO:Llyiahf/vczjk/dp8;

    return-void
.end method


# virtual methods
.method public OoooOO0()Llyiahf/vczjk/jg5;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/k23;->o0000Ooo()Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v0

    return-object v0
.end method

.method public final o000000()Llyiahf/vczjk/n3a;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/k23;->o0000Ooo()Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    return-object v0
.end method

.method public final o000000o()Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/k23;->o0000Ooo()Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000o()Z

    move-result v0

    return v0
.end method

.method public abstract o00000oO(Llyiahf/vczjk/h72;Llyiahf/vczjk/h72;)Ljava/lang/String;
.end method

.method public abstract o0000Ooo()Llyiahf/vczjk/dp8;
.end method

.method public final o00ooo()Ljava/util/List;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/k23;->o0000Ooo()Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final o0OOO0o()Llyiahf/vczjk/d3a;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/k23;->o0000Ooo()Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o0OOO0o()Llyiahf/vczjk/d3a;

    move-result-object v0

    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    sget-object v0, Llyiahf/vczjk/h72;->OooO0o0:Llyiahf/vczjk/h72;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/h72;->OoooOOo(Llyiahf/vczjk/uk4;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
