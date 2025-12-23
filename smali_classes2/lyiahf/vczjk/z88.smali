.class public final Llyiahf/vczjk/z88;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0Oo:Llyiahf/vczjk/pp3;

.field public static final synthetic OooO0o0:[Llyiahf/vczjk/th4;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/oo0o0Oo;

.field public final OooO0O0:Llyiahf/vczjk/oe3;

.field public final OooO0OO:Llyiahf/vczjk/o45;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/z88;

    const-string v2, "scopeForOwnerModule"

    const-string v3, "getScopeForOwnerModule()Lorg/jetbrains/kotlin/resolve/scopes/MemberScope;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const/4 v1, 0x1

    new-array v1, v1, [Llyiahf/vczjk/th4;

    aput-object v0, v1, v4

    sput-object v1, Llyiahf/vczjk/z88;->OooO0o0:[Llyiahf/vczjk/th4;

    new-instance v0, Llyiahf/vczjk/pp3;

    const/16 v1, 0x18

    invoke-direct {v0, v1}, Llyiahf/vczjk/pp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/z88;->OooO0Oo:Llyiahf/vczjk/pp3;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/oo0o0Oo;Llyiahf/vczjk/q45;Llyiahf/vczjk/oe3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/z88;->OooO00o:Llyiahf/vczjk/oo0o0Oo;

    iput-object p3, p0, Llyiahf/vczjk/z88;->OooO0O0:Llyiahf/vczjk/oe3;

    new-instance p1, Llyiahf/vczjk/o0oOOo;

    const/16 p3, 0x1d

    invoke-direct {p1, p0, p3}, Llyiahf/vczjk/o0oOOo;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p3, Llyiahf/vczjk/o45;

    invoke-direct {p3, p2, p1}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object p3, p0, Llyiahf/vczjk/z88;->OooO0OO:Llyiahf/vczjk/o45;

    return-void
.end method
