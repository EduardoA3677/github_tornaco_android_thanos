.class public final Llyiahf/vczjk/ns4;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ql5;
.implements Llyiahf/vczjk/go4;


# static fields
.field public static final OooOooo:Llyiahf/vczjk/ks4;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/os4;

.field public OooOoo:Z

.field public OooOoo0:Llyiahf/vczjk/vz5;

.field public OooOooO:Llyiahf/vczjk/nf6;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/ks4;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/ns4;->OooOooo:Llyiahf/vczjk/ks4;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 1

    invoke-interface {p2, p3, p4}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget p4, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    new-instance v0, Llyiahf/vczjk/ms4;

    invoke-direct {v0, p2}, Llyiahf/vczjk/ms4;-><init>(Llyiahf/vczjk/ow6;)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, p3, p4, p2, v0}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method

.method public final OoooO0O()Llyiahf/vczjk/e16;
    .locals 4

    sget-object v0, Llyiahf/vczjk/nb0;->OooO00o:Llyiahf/vczjk/ie7;

    new-instance v1, Llyiahf/vczjk/xn6;

    invoke-direct {v1, v0, p0}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v0, Llyiahf/vczjk/rp8;

    invoke-virtual {v1}, Llyiahf/vczjk/xn6;->OooO0OO()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ie7;

    invoke-direct {v0, v2}, Llyiahf/vczjk/rp8;-><init>(Llyiahf/vczjk/ie7;)V

    invoke-virtual {v1}, Llyiahf/vczjk/xn6;->OooO0OO()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ie7;

    invoke-virtual {v1}, Llyiahf/vczjk/xn6;->OooO0Oo()Ljava/lang/Object;

    move-result-object v1

    if-ne v3, v2, :cond_0

    goto :goto_0

    :cond_0
    const-string v2, "Check failed."

    invoke-static {v2}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :goto_0
    iget-object v2, v0, Llyiahf/vczjk/rp8;->OooOOO0:Llyiahf/vczjk/qs5;

    check-cast v2, Llyiahf/vczjk/fw8;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    return-object v0
.end method

.method public final o00000OO(Llyiahf/vczjk/js4;I)Z
    .locals 3

    const/4 v0, 0x5

    const/4 v1, 0x1

    if-ne p2, v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x6

    if-ne p2, v0, :cond_1

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/ns4;->OooOooO:Llyiahf/vczjk/nf6;

    sget-object v2, Llyiahf/vczjk/nf6;->OooOOO:Llyiahf/vczjk/nf6;

    if-ne v0, v2, :cond_5

    goto :goto_4

    :cond_1
    const/4 v0, 0x3

    if-ne p2, v0, :cond_2

    goto :goto_1

    :cond_2
    const/4 v0, 0x4

    if-ne p2, v0, :cond_3

    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/ns4;->OooOooO:Llyiahf/vczjk/nf6;

    sget-object v2, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    if-ne v0, v2, :cond_5

    goto :goto_4

    :cond_3
    if-ne p2, v1, :cond_4

    goto :goto_2

    :cond_4
    const/4 v0, 0x2

    if-ne p2, v0, :cond_8

    :cond_5
    :goto_2
    invoke-virtual {p0, p2}, Llyiahf/vczjk/ns4;->o00000Oo(I)Z

    move-result p2

    if-eqz p2, :cond_6

    iget p1, p1, Llyiahf/vczjk/js4;->OooO0O0:I

    iget-object p2, p0, Llyiahf/vczjk/ns4;->OooOoOO:Llyiahf/vczjk/os4;

    invoke-interface {p2}, Llyiahf/vczjk/os4;->OooO00o()I

    move-result p2

    sub-int/2addr p2, v1

    if-ge p1, p2, :cond_7

    goto :goto_3

    :cond_6
    iget p1, p1, Llyiahf/vczjk/js4;->OooO00o:I

    if-lez p1, :cond_7

    :goto_3
    return v1

    :cond_7
    :goto_4
    const/4 p1, 0x0

    return p1

    :cond_8
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "Lazy list does not support beyond bounds layout for the specified direction"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final o00000Oo(I)Z
    .locals 2

    const/4 v0, 0x1

    if-ne p1, v0, :cond_0

    goto :goto_1

    :cond_0
    const/4 v1, 0x2

    if-ne p1, v1, :cond_1

    goto :goto_0

    :cond_1
    const/4 v1, 0x5

    if-ne p1, v1, :cond_2

    iget-boolean p1, p0, Llyiahf/vczjk/ns4;->OooOoo:Z

    return p1

    :cond_2
    const/4 v1, 0x6

    if-ne p1, v1, :cond_3

    iget-boolean p1, p0, Llyiahf/vczjk/ns4;->OooOoo:Z

    if-nez p1, :cond_9

    goto :goto_0

    :cond_3
    const/4 v1, 0x3

    if-ne p1, v1, :cond_6

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object p1

    iget-object p1, p1, Llyiahf/vczjk/ro4;->Oooo0o0:Llyiahf/vczjk/yn4;

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    if-eqz p1, :cond_5

    if-ne p1, v0, :cond_4

    iget-boolean p1, p0, Llyiahf/vczjk/ns4;->OooOoo:Z

    if-nez p1, :cond_9

    goto :goto_0

    :cond_4
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_5
    iget-boolean p1, p0, Llyiahf/vczjk/ns4;->OooOoo:Z

    return p1

    :cond_6
    const/4 v1, 0x4

    if-ne p1, v1, :cond_a

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object p1

    iget-object p1, p1, Llyiahf/vczjk/ro4;->Oooo0o0:Llyiahf/vczjk/yn4;

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    if-eqz p1, :cond_8

    if-ne p1, v0, :cond_7

    iget-boolean p1, p0, Llyiahf/vczjk/ns4;->OooOoo:Z

    return p1

    :cond_7
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_8
    iget-boolean p1, p0, Llyiahf/vczjk/ns4;->OooOoo:Z

    if-nez p1, :cond_9

    :goto_0
    return v0

    :cond_9
    :goto_1
    const/4 p1, 0x0

    return p1

    :cond_a
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Lazy list does not support beyond bounds layout for the specified direction"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
