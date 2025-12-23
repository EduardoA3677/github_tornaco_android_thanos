.class public final Llyiahf/vczjk/wg4;
.super Llyiahf/vczjk/vf4;
.source "SourceFile"


# static fields
.field public static final synthetic OooO0oO:[Llyiahf/vczjk/th4;


# instance fields
.field public final OooO0OO:Llyiahf/vczjk/wm7;

.field public final OooO0Oo:Llyiahf/vczjk/wm7;

.field public final OooO0o:Ljava/lang/Object;

.field public final OooO0o0:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/wg4;

    const-string v2, "kotlinClass"

    const-string v3, "getKotlinClass()Lorg/jetbrains/kotlin/descriptors/runtime/components/ReflectKotlinClass;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v2, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const-string v3, "scope"

    const-string v5, "getScope()Lorg/jetbrains/kotlin/resolve/scopes/MemberScope;"

    invoke-static {v1, v3, v5, v4, v2}, Llyiahf/vczjk/u81;->OooOOOo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/zm7;)Llyiahf/vczjk/mh4;

    move-result-object v3

    const-string v5, "members"

    const-string v6, "getMembers()Ljava/util/Collection;"

    invoke-static {v1, v5, v6, v4, v2}, Llyiahf/vczjk/u81;->OooOOOo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/zm7;)Llyiahf/vczjk/mh4;

    move-result-object v1

    const/4 v2, 0x3

    new-array v2, v2, [Llyiahf/vczjk/th4;

    aput-object v0, v2, v4

    const/4 v0, 0x1

    aput-object v3, v2, v0

    const/4 v0, 0x2

    aput-object v1, v2, v0

    sput-object v2, Llyiahf/vczjk/wg4;->OooO0oO:[Llyiahf/vczjk/th4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/yg4;)V
    .locals 4

    invoke-direct {p0, p1}, Llyiahf/vczjk/vf4;-><init>(Llyiahf/vczjk/yf4;)V

    new-instance v0, Llyiahf/vczjk/tg4;

    const/4 v1, 0x1

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/tg4;-><init>(Llyiahf/vczjk/yg4;I)V

    const/4 v1, 0x0

    invoke-static {v1, v0}, Llyiahf/vczjk/vo6;->OooOO0o(Llyiahf/vczjk/eo0;Llyiahf/vczjk/le3;)Llyiahf/vczjk/wm7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/wg4;->OooO0OO:Llyiahf/vczjk/wm7;

    new-instance v0, Llyiahf/vczjk/ug4;

    const/4 v2, 0x0

    invoke-direct {v0, p0, v2}, Llyiahf/vczjk/ug4;-><init>(Llyiahf/vczjk/wg4;I)V

    invoke-static {v1, v0}, Llyiahf/vczjk/vo6;->OooOO0o(Llyiahf/vczjk/eo0;Llyiahf/vczjk/le3;)Llyiahf/vczjk/wm7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/wg4;->OooO0Oo:Llyiahf/vczjk/wm7;

    sget-object v0, Llyiahf/vczjk/ww4;->OooOOO0:Llyiahf/vczjk/ww4;

    new-instance v2, Llyiahf/vczjk/vg4;

    invoke-direct {v2, p0, p1}, Llyiahf/vczjk/vg4;-><init>(Llyiahf/vczjk/wg4;Llyiahf/vczjk/yg4;)V

    invoke-static {v0, v2}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/wg4;->OooO0o0:Ljava/lang/Object;

    new-instance v2, Llyiahf/vczjk/ug4;

    const/4 v3, 0x1

    invoke-direct {v2, p0, v3}, Llyiahf/vczjk/ug4;-><init>(Llyiahf/vczjk/wg4;I)V

    invoke-static {v0, v2}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/wg4;->OooO0o:Ljava/lang/Object;

    new-instance v0, Llyiahf/vczjk/vg4;

    invoke-direct {v0, p1, p0}, Llyiahf/vczjk/vg4;-><init>(Llyiahf/vczjk/yg4;Llyiahf/vczjk/wg4;)V

    invoke-static {v1, v0}, Llyiahf/vczjk/vo6;->OooOO0o(Llyiahf/vczjk/eo0;Llyiahf/vczjk/le3;)Llyiahf/vczjk/wm7;

    return-void
.end method
