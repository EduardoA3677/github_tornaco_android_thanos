.class public abstract Llyiahf/vczjk/qr1;
.super Llyiahf/vczjk/o000O0o;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ap1;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/pr1;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/pr1;

    sget-object v1, Llyiahf/vczjk/vp3;->OooOOOO:Llyiahf/vczjk/vp3;

    new-instance v2, Llyiahf/vczjk/ow;

    const/16 v3, 0x15

    invoke-direct {v2, v3}, Llyiahf/vczjk/ow;-><init>(I)V

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/pr1;-><init>(Llyiahf/vczjk/nr1;Llyiahf/vczjk/oe3;)V

    sput-object v0, Llyiahf/vczjk/qr1;->OooOOO:Llyiahf/vczjk/pr1;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/vp3;->OooOOOO:Llyiahf/vczjk/vp3;

    invoke-direct {p0, v0}, Llyiahf/vczjk/o000O0o;-><init>(Llyiahf/vczjk/nr1;)V

    return-void
.end method


# virtual methods
.method public final OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;
    .locals 2

    const-string v0, "key"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p1, Llyiahf/vczjk/pr1;

    if-eqz v0, :cond_1

    check-cast p1, Llyiahf/vczjk/pr1;

    iget-object v0, p0, Llyiahf/vczjk/o000O0o;->OooOOO0:Llyiahf/vczjk/nr1;

    if-eq v0, p1, :cond_0

    iget-object v1, p1, Llyiahf/vczjk/pr1;->OooOOO:Llyiahf/vczjk/nr1;

    if-ne v1, v0, :cond_2

    :cond_0
    iget-object p1, p1, Llyiahf/vczjk/pr1;->OooOOO0:Llyiahf/vczjk/oe3;

    invoke-interface {p1, p0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/mr1;

    if-eqz p1, :cond_2

    return-object p1

    :cond_1
    sget-object v0, Llyiahf/vczjk/vp3;->OooOOOO:Llyiahf/vczjk/vp3;

    if-ne v0, p1, :cond_2

    return-object p0

    :cond_2
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooOoO(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/or1;
    .locals 3

    const-string v0, "key"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p1, Llyiahf/vczjk/pr1;

    sget-object v1, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    if-eqz v0, :cond_2

    check-cast p1, Llyiahf/vczjk/pr1;

    iget-object v0, p0, Llyiahf/vczjk/o000O0o;->OooOOO0:Llyiahf/vczjk/nr1;

    if-eq v0, p1, :cond_1

    iget-object v2, p1, Llyiahf/vczjk/pr1;->OooOOO:Llyiahf/vczjk/nr1;

    if-ne v2, v0, :cond_0

    goto :goto_0

    :cond_0
    return-object p0

    :cond_1
    :goto_0
    iget-object p1, p1, Llyiahf/vczjk/pr1;->OooOOO0:Llyiahf/vczjk/oe3;

    invoke-interface {p1, p0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/mr1;

    if-eqz p1, :cond_3

    goto :goto_1

    :cond_2
    sget-object v0, Llyiahf/vczjk/vp3;->OooOOOO:Llyiahf/vczjk/vp3;

    if-ne v0, p1, :cond_3

    :goto_1
    return-object v1

    :cond_3
    return-object p0
.end method

.method public abstract o00000o0(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V
.end method

.method public o00000oO(Llyiahf/vczjk/or1;)Z
    .locals 0

    instance-of p1, p0, Llyiahf/vczjk/h8a;

    xor-int/lit8 p1, p1, 0x1

    return p1
.end method

.method public o00000oo(I)Llyiahf/vczjk/qr1;
    .locals 1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOoOO(I)V

    new-instance v0, Llyiahf/vczjk/az4;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/az4;-><init>(Llyiahf/vczjk/qr1;I)V

    return-object v0
.end method

.method public o0000Ooo(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V
    .locals 0

    invoke-static {p0, p1, p2}, Llyiahf/vczjk/dn8;->o0ooOO0(Llyiahf/vczjk/qr1;Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V

    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v1, 0x40

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-static {p0}, Llyiahf/vczjk/r02;->OooOo0(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
