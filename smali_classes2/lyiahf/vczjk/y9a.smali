.class public final enum Llyiahf/vczjk/y9a;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/y9a;

.field public static final enum OooOOO0:Llyiahf/vczjk/y9a;

.field public static final enum OooOOOO:Llyiahf/vczjk/y9a;

.field public static final enum OooOOOo:Llyiahf/vczjk/y9a;

.field public static final synthetic OooOOo0:[Llyiahf/vczjk/y9a;


# instance fields
.field private final classId:Llyiahf/vczjk/hy0;

.field private final typeName:Llyiahf/vczjk/qt5;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    new-instance v0, Llyiahf/vczjk/y9a;

    const-string v1, "kotlin/UByteArray"

    const/4 v2, 0x0

    invoke-static {v1, v2}, Llyiahf/vczjk/jp8;->OooOo0o(Ljava/lang/String;Z)Llyiahf/vczjk/hy0;

    move-result-object v1

    const-string v3, "UBYTEARRAY"

    invoke-direct {v0, v3, v2, v1}, Llyiahf/vczjk/y9a;-><init>(Ljava/lang/String;ILlyiahf/vczjk/hy0;)V

    sput-object v0, Llyiahf/vczjk/y9a;->OooOOO0:Llyiahf/vczjk/y9a;

    new-instance v1, Llyiahf/vczjk/y9a;

    const-string v3, "kotlin/UShortArray"

    invoke-static {v3, v2}, Llyiahf/vczjk/jp8;->OooOo0o(Ljava/lang/String;Z)Llyiahf/vczjk/hy0;

    move-result-object v3

    const-string v4, "USHORTARRAY"

    const/4 v5, 0x1

    invoke-direct {v1, v4, v5, v3}, Llyiahf/vczjk/y9a;-><init>(Ljava/lang/String;ILlyiahf/vczjk/hy0;)V

    sput-object v1, Llyiahf/vczjk/y9a;->OooOOO:Llyiahf/vczjk/y9a;

    new-instance v3, Llyiahf/vczjk/y9a;

    const-string v4, "kotlin/UIntArray"

    invoke-static {v4, v2}, Llyiahf/vczjk/jp8;->OooOo0o(Ljava/lang/String;Z)Llyiahf/vczjk/hy0;

    move-result-object v4

    const-string v5, "UINTARRAY"

    const/4 v6, 0x2

    invoke-direct {v3, v5, v6, v4}, Llyiahf/vczjk/y9a;-><init>(Ljava/lang/String;ILlyiahf/vczjk/hy0;)V

    sput-object v3, Llyiahf/vczjk/y9a;->OooOOOO:Llyiahf/vczjk/y9a;

    new-instance v4, Llyiahf/vczjk/y9a;

    const-string v5, "kotlin/ULongArray"

    invoke-static {v5, v2}, Llyiahf/vczjk/jp8;->OooOo0o(Ljava/lang/String;Z)Llyiahf/vczjk/hy0;

    move-result-object v2

    const-string v5, "ULONGARRAY"

    const/4 v6, 0x3

    invoke-direct {v4, v5, v6, v2}, Llyiahf/vczjk/y9a;-><init>(Ljava/lang/String;ILlyiahf/vczjk/hy0;)V

    sput-object v4, Llyiahf/vczjk/y9a;->OooOOOo:Llyiahf/vczjk/y9a;

    filled-new-array {v0, v1, v3, v4}, [Llyiahf/vczjk/y9a;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/y9a;->OooOOo0:[Llyiahf/vczjk/y9a;

    invoke-static {v0}, Llyiahf/vczjk/yi4;->OoooO0([Ljava/lang/Enum;)Llyiahf/vczjk/np2;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILlyiahf/vczjk/hy0;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    iput-object p3, p0, Llyiahf/vczjk/y9a;->classId:Llyiahf/vczjk/hy0;

    invoke-virtual {p3}, Llyiahf/vczjk/hy0;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/y9a;->typeName:Llyiahf/vczjk/qt5;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/y9a;
    .locals 1

    const-class v0, Llyiahf/vczjk/y9a;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/y9a;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/y9a;
    .locals 1

    sget-object v0, Llyiahf/vczjk/y9a;->OooOOo0:[Llyiahf/vczjk/y9a;

    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/y9a;

    return-object v0
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/qt5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/y9a;->typeName:Llyiahf/vczjk/qt5;

    return-object v0
.end method
