.class public final Llyiahf/vczjk/a52;
.super Llyiahf/vczjk/o52;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ev1;
.implements Llyiahf/vczjk/pt7;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/dp8;

.field public final OooOOOO:Z


# direct methods
.method static constructor <clinit>()V
    .locals 0

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/dp8;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/a52;->OooOOO:Llyiahf/vczjk/dp8;

    iput-boolean p2, p0, Llyiahf/vczjk/a52;->OooOOOO:Z

    return-void
.end method


# virtual methods
.method public final Oooo0oO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;
    .locals 1

    const-string v0, "replacement"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object p1

    iget-boolean v0, p0, Llyiahf/vczjk/a52;->OooOOOO:Z

    invoke-static {p1, v0}, Llyiahf/vczjk/ll6;->OooOO0o(Llyiahf/vczjk/iaa;Z)Llyiahf/vczjk/iaa;

    move-result-object p1

    return-object p1
.end method

.method public final o000000o()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final o00000oO(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;
    .locals 2

    const-string v0, "newAttributes"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/a52;

    iget-object v1, p0, Llyiahf/vczjk/a52;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/dp8;->o00000oO(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;

    move-result-object p1

    iget-boolean v1, p0, Llyiahf/vczjk/a52;->OooOOOO:Z

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/a52;-><init>(Llyiahf/vczjk/dp8;Z)V

    return-object v0
.end method

.method public final o00000oo()Llyiahf/vczjk/dp8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/a52;->OooOOO:Llyiahf/vczjk/dp8;

    return-object v0
.end method

.method public final o0000O00(Llyiahf/vczjk/dp8;)Llyiahf/vczjk/o52;
    .locals 2

    new-instance v0, Llyiahf/vczjk/a52;

    iget-boolean v1, p0, Llyiahf/vczjk/a52;->OooOOOO:Z

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/a52;-><init>(Llyiahf/vczjk/dp8;Z)V

    return-object v0
.end method

.method public final o0000Ooo(Z)Llyiahf/vczjk/dp8;
    .locals 1

    if-eqz p1, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/a52;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/dp8;->o0000Ooo(Z)Llyiahf/vczjk/dp8;

    move-result-object p1

    return-object p1

    :cond_0
    return-object p0
.end method

.method public final o000oOoO()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/a52;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v0

    instance-of v0, v0, Llyiahf/vczjk/t4a;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/a52;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, " & Any"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
