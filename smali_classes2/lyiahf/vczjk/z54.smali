.class public Llyiahf/vczjk/z54;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/f07;


# static fields
.field public static final synthetic OooO0o0:[Llyiahf/vczjk/th4;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/hc3;

.field public final OooO0O0:Llyiahf/vczjk/sx8;

.field public final OooO0OO:Llyiahf/vczjk/o45;

.field public final OooO0Oo:Llyiahf/vczjk/y54;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/z54;

    const-string v2, "type"

    const-string v3, "getType()Lorg/jetbrains/kotlin/types/SimpleType;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const/4 v1, 0x1

    new-array v1, v1, [Llyiahf/vczjk/th4;

    aput-object v0, v1, v4

    sput-object v1, Llyiahf/vczjk/z54;->OooO0o0:[Llyiahf/vczjk/th4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/sl7;Llyiahf/vczjk/hc3;)V
    .locals 3

    const-string v0, "c"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "fqName"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p3, p0, Llyiahf/vczjk/z54;->OooO00o:Llyiahf/vczjk/hc3;

    iget-object p3, p1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast p3, Llyiahf/vczjk/s64;

    if-eqz p2, :cond_0

    iget-object v0, p3, Llyiahf/vczjk/s64;->OooOO0:Llyiahf/vczjk/rp3;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/rp3;->OooOo0O(Llyiahf/vczjk/k64;)Llyiahf/vczjk/hz7;

    move-result-object v0

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    :goto_0
    iput-object v0, p0, Llyiahf/vczjk/z54;->OooO0O0:Llyiahf/vczjk/sx8;

    iget-object p3, p3, Llyiahf/vczjk/s64;->OooO00o:Llyiahf/vczjk/q45;

    new-instance v0, Llyiahf/vczjk/o0O000;

    const/16 v1, 0xe

    const/4 v2, 0x0

    invoke-direct {v0, v1, p1, p0, v2}, Llyiahf/vczjk/o0O000;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Llyiahf/vczjk/o45;

    invoke-direct {p1, p3, v0}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object p1, p0, Llyiahf/vczjk/z54;->OooO0OO:Llyiahf/vczjk/o45;

    if-eqz p2, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/sl7;->OooO0O0()Ljava/util/ArrayList;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/d21;->o00ooo(Ljava/lang/Iterable;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/y54;

    goto :goto_1

    :cond_1
    const/4 p1, 0x0

    :goto_1
    iput-object p1, p0, Llyiahf/vczjk/z54;->OooO0Oo:Llyiahf/vczjk/y54;

    return-void
.end method


# virtual methods
.method public OooO()Ljava/util/Map;
    .locals 1

    sget-object v0, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    return-object v0
.end method

.method public final OooO0oO()Llyiahf/vczjk/sx8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z54;->OooO0O0:Llyiahf/vczjk/sx8;

    return-object v0
.end method

.method public final OooO0oo()Llyiahf/vczjk/hc3;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z54;->OooO00o:Llyiahf/vczjk/hc3;

    return-object v0
.end method

.method public final getType()Llyiahf/vczjk/uk4;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/z54;->OooO0OO:Llyiahf/vczjk/o45;

    sget-object v1, Llyiahf/vczjk/z54;->OooO0o0:[Llyiahf/vczjk/th4;

    const/4 v2, 0x0

    aget-object v1, v1, v2

    invoke-static {v0, v1}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/dp8;

    return-object v0
.end method
