.class public final Llyiahf/vczjk/fn7;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0Oo:Llyiahf/vczjk/tp3;

.field public static final synthetic OooO0o0:[Llyiahf/vczjk/th4;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ld9;

.field public final OooO0O0:Ljava/lang/Object;

.field public final OooO0OO:Llyiahf/vczjk/sp3;


# direct methods
.method static constructor <clinit>()V
    .locals 12

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/fn7;

    const-string v2, "kClass"

    const-string v3, "getKClass()Lorg/jetbrains/kotlin/descriptors/ClassDescriptor;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v2, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const-string v3, "kProperty"

    const-string v5, "getKProperty()Lorg/jetbrains/kotlin/descriptors/ClassDescriptor;"

    invoke-static {v1, v3, v5, v4, v2}, Llyiahf/vczjk/u81;->OooOOOo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/zm7;)Llyiahf/vczjk/mh4;

    move-result-object v3

    const-string v5, "kProperty0"

    const-string v6, "getKProperty0()Lorg/jetbrains/kotlin/descriptors/ClassDescriptor;"

    invoke-static {v1, v5, v6, v4, v2}, Llyiahf/vczjk/u81;->OooOOOo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/zm7;)Llyiahf/vczjk/mh4;

    move-result-object v5

    const-string v6, "kProperty1"

    const-string v7, "getKProperty1()Lorg/jetbrains/kotlin/descriptors/ClassDescriptor;"

    invoke-static {v1, v6, v7, v4, v2}, Llyiahf/vczjk/u81;->OooOOOo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/zm7;)Llyiahf/vczjk/mh4;

    move-result-object v6

    const-string v7, "kProperty2"

    const-string v8, "getKProperty2()Lorg/jetbrains/kotlin/descriptors/ClassDescriptor;"

    invoke-static {v1, v7, v8, v4, v2}, Llyiahf/vczjk/u81;->OooOOOo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/zm7;)Llyiahf/vczjk/mh4;

    move-result-object v7

    const-string v8, "kMutableProperty0"

    const-string v9, "getKMutableProperty0()Lorg/jetbrains/kotlin/descriptors/ClassDescriptor;"

    invoke-static {v1, v8, v9, v4, v2}, Llyiahf/vczjk/u81;->OooOOOo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/zm7;)Llyiahf/vczjk/mh4;

    move-result-object v8

    const-string v9, "kMutableProperty1"

    const-string v10, "getKMutableProperty1()Lorg/jetbrains/kotlin/descriptors/ClassDescriptor;"

    invoke-static {v1, v9, v10, v4, v2}, Llyiahf/vczjk/u81;->OooOOOo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/zm7;)Llyiahf/vczjk/mh4;

    move-result-object v9

    const-string v10, "kMutableProperty2"

    const-string v11, "getKMutableProperty2()Lorg/jetbrains/kotlin/descriptors/ClassDescriptor;"

    invoke-static {v1, v10, v11, v4, v2}, Llyiahf/vczjk/u81;->OooOOOo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/zm7;)Llyiahf/vczjk/mh4;

    move-result-object v1

    const/16 v2, 0x8

    new-array v2, v2, [Llyiahf/vczjk/th4;

    aput-object v0, v2, v4

    const/4 v0, 0x1

    aput-object v3, v2, v0

    const/4 v0, 0x2

    aput-object v5, v2, v0

    const/4 v0, 0x3

    aput-object v6, v2, v0

    const/4 v0, 0x4

    aput-object v7, v2, v0

    const/4 v0, 0x5

    aput-object v8, v2, v0

    const/4 v0, 0x6

    aput-object v9, v2, v0

    const/4 v0, 0x7

    aput-object v1, v2, v0

    sput-object v2, Llyiahf/vczjk/fn7;->OooO0o0:[Llyiahf/vczjk/th4;

    new-instance v0, Llyiahf/vczjk/tp3;

    const/16 v1, 0x16

    invoke-direct {v0, v1}, Llyiahf/vczjk/tp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/fn7;->OooO0Oo:Llyiahf/vczjk/tp3;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/dm5;Llyiahf/vczjk/ld9;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/fn7;->OooO00o:Llyiahf/vczjk/ld9;

    sget-object p2, Llyiahf/vczjk/ww4;->OooOOO0:Llyiahf/vczjk/ww4;

    new-instance v0, Llyiahf/vczjk/gd4;

    const/4 v1, 0x2

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/gd4;-><init>(Llyiahf/vczjk/dm5;I)V

    invoke-static {p2, v0}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/fn7;->OooO0O0:Ljava/lang/Object;

    new-instance p1, Llyiahf/vczjk/sp3;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fn7;->OooO0OO:Llyiahf/vczjk/sp3;

    return-void
.end method
