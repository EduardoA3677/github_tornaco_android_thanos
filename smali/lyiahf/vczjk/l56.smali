.class public final Llyiahf/vczjk/l56;
.super Llyiahf/vczjk/r56;
.source "SourceFile"


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/l56;

.field public static final OooOOOo:Llyiahf/vczjk/l56;

.field private static final serialVersionUID:J = 0x1L


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/l56;

    const/4 v1, 0x0

    invoke-static {v1}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    move-result-object v1

    sget-object v2, Ljava/lang/Character;->TYPE:Ljava/lang/Class;

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/l56;-><init>(Ljava/lang/Class;Ljava/lang/Character;)V

    sput-object v0, Llyiahf/vczjk/l56;->OooOOOO:Llyiahf/vczjk/l56;

    new-instance v0, Llyiahf/vczjk/l56;

    const-class v1, Ljava/lang/Character;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/l56;-><init>(Ljava/lang/Class;Ljava/lang/Character;)V

    sput-object v0, Llyiahf/vczjk/l56;->OooOOOo:Llyiahf/vczjk/l56;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Class;Ljava/lang/Character;)V
    .locals 1

    const/4 v0, 0x0

    invoke-static {v0}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    move-result-object v0

    invoke-direct {p0, p2, v0, p1}, Llyiahf/vczjk/r56;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Class;)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 3

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0OoOo0()I

    move-result v0

    const/4 v1, 0x3

    if-eq v0, v1, :cond_4

    const/16 v1, 0xb

    if-eq v0, v1, :cond_3

    const/4 v1, 0x6

    if-eq v0, v1, :cond_0

    const/4 v1, 0x7

    if-ne v0, v1, :cond_2

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->Oooo0oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o00000o0()I

    move-result v0

    if-ltz v0, :cond_2

    const v1, 0xffff

    if-gt v0, v1, :cond_2

    int-to-char p1, v0

    invoke-static {p1}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v1

    const/4 v2, 0x1

    if-ne v1, v2, :cond_1

    const/4 p1, 0x0

    invoke-virtual {v0, p1}, Ljava/lang/String;->charAt(I)C

    move-result p1

    invoke-static {p1}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    move-result-object p1

    return-object p1

    :cond_1
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v0

    if-nez v0, :cond_2

    iget-boolean p2, p0, Llyiahf/vczjk/r56;->_primitive:Z

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->OooOOo0(Llyiahf/vczjk/v72;Z)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Character;

    return-object p1

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    const/4 p1, 0x0

    throw p1

    :cond_3
    iget-boolean p2, p0, Llyiahf/vczjk/r56;->_primitive:Z

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->OooOOoo(Llyiahf/vczjk/v72;Z)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Character;

    return-object p1

    :cond_4
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->OooOo0O(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Character;

    return-object p1
.end method
