.class public final Llyiahf/vczjk/jd4;
.super Llyiahf/vczjk/hk4;
.source "SourceFile"


# static fields
.field public static final synthetic OooO0oo:[Llyiahf/vczjk/th4;


# instance fields
.field public OooO0o:Llyiahf/vczjk/gd4;

.field public final OooO0oO:Llyiahf/vczjk/o45;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/jd4;

    const-string v2, "customizer"

    const-string v3, "getCustomizer()Lorg/jetbrains/kotlin/builtins/jvm/JvmBuiltInsCustomizer;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const/4 v1, 0x1

    new-array v1, v1, [Llyiahf/vczjk/th4;

    aput-object v0, v1, v4

    sput-object v1, Llyiahf/vczjk/jd4;->OooO0oo:[Llyiahf/vczjk/th4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/q45;)V
    .locals 3

    sget-object v0, Llyiahf/vczjk/hd4;->OooOOO0:[Llyiahf/vczjk/hd4;

    invoke-direct {p0, p1}, Llyiahf/vczjk/hk4;-><init>(Llyiahf/vczjk/q45;)V

    new-instance v0, Llyiahf/vczjk/o0O000;

    const/16 v1, 0x10

    const/4 v2, 0x0

    invoke-direct {v0, v1, p0, p1, v2}, Llyiahf/vczjk/o0O000;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    new-instance v1, Llyiahf/vczjk/o45;

    invoke-direct {v1, p1, v0}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v1, p0, Llyiahf/vczjk/jd4;->OooO0oO:Llyiahf/vczjk/o45;

    return-void
.end method


# virtual methods
.method public final OooO0Oo()Llyiahf/vczjk/n1;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/jd4;->Oooo0OO()Llyiahf/vczjk/nd4;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOO0()Ljava/lang/Iterable;
    .locals 5

    invoke-super {p0}, Llyiahf/vczjk/hk4;->OooOOO0()Ljava/lang/Iterable;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/fd4;

    iget-object v2, p0, Llyiahf/vczjk/hk4;->OooO0Oo:Llyiahf/vczjk/q45;

    invoke-virtual {p0}, Llyiahf/vczjk/hk4;->OooOO0o()Llyiahf/vczjk/dm5;

    move-result-object v3

    const-string v4, "getBuiltInsModule(...)"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/fd4;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/dm5;)V

    invoke-static {v0, v1}, Llyiahf/vczjk/d21;->o00000(Ljava/lang/Iterable;Ljava/lang/Object;)Ljava/util/ArrayList;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOo0()Llyiahf/vczjk/cx6;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/jd4;->Oooo0OO()Llyiahf/vczjk/nd4;

    move-result-object v0

    return-object v0
.end method

.method public final Oooo0OO()Llyiahf/vczjk/nd4;
    .locals 2

    sget-object v0, Llyiahf/vczjk/jd4;->OooO0oo:[Llyiahf/vczjk/th4;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    iget-object v1, p0, Llyiahf/vczjk/jd4;->OooO0oO:Llyiahf/vczjk/o45;

    invoke-static {v1, v0}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nd4;

    return-object v0
.end method
