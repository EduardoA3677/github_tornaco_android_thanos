.class public final enum Llyiahf/vczjk/z9a;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final synthetic OooOOO0:[Llyiahf/vczjk/z9a;


# instance fields
.field private final arrayClassId:Llyiahf/vczjk/hy0;

.field private final classId:Llyiahf/vczjk/hy0;

.field private final typeName:Llyiahf/vczjk/qt5;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    new-instance v0, Llyiahf/vczjk/z9a;

    const-string v1, "kotlin/UByte"

    const/4 v2, 0x0

    invoke-static {v1, v2}, Llyiahf/vczjk/jp8;->OooOo0o(Ljava/lang/String;Z)Llyiahf/vczjk/hy0;

    move-result-object v1

    const-string v3, "UBYTE"

    invoke-direct {v0, v3, v2, v1}, Llyiahf/vczjk/z9a;-><init>(Ljava/lang/String;ILlyiahf/vczjk/hy0;)V

    new-instance v1, Llyiahf/vczjk/z9a;

    const-string v3, "kotlin/UShort"

    invoke-static {v3, v2}, Llyiahf/vczjk/jp8;->OooOo0o(Ljava/lang/String;Z)Llyiahf/vczjk/hy0;

    move-result-object v3

    const-string v4, "USHORT"

    const/4 v5, 0x1

    invoke-direct {v1, v4, v5, v3}, Llyiahf/vczjk/z9a;-><init>(Ljava/lang/String;ILlyiahf/vczjk/hy0;)V

    new-instance v3, Llyiahf/vczjk/z9a;

    const-string v4, "kotlin/UInt"

    invoke-static {v4, v2}, Llyiahf/vczjk/jp8;->OooOo0o(Ljava/lang/String;Z)Llyiahf/vczjk/hy0;

    move-result-object v4

    const-string v5, "UINT"

    const/4 v6, 0x2

    invoke-direct {v3, v5, v6, v4}, Llyiahf/vczjk/z9a;-><init>(Ljava/lang/String;ILlyiahf/vczjk/hy0;)V

    new-instance v4, Llyiahf/vczjk/z9a;

    const-string v5, "kotlin/ULong"

    invoke-static {v5, v2}, Llyiahf/vczjk/jp8;->OooOo0o(Ljava/lang/String;Z)Llyiahf/vczjk/hy0;

    move-result-object v2

    const-string v5, "ULONG"

    const/4 v6, 0x3

    invoke-direct {v4, v5, v6, v2}, Llyiahf/vczjk/z9a;-><init>(Ljava/lang/String;ILlyiahf/vczjk/hy0;)V

    filled-new-array {v0, v1, v3, v4}, [Llyiahf/vczjk/z9a;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/z9a;->OooOOO0:[Llyiahf/vczjk/z9a;

    invoke-static {v0}, Llyiahf/vczjk/yi4;->OoooO0([Ljava/lang/Enum;)Llyiahf/vczjk/np2;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILlyiahf/vczjk/hy0;)V
    .locals 1

    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    iput-object p3, p0, Llyiahf/vczjk/z9a;->classId:Llyiahf/vczjk/hy0;

    invoke-virtual {p3}, Llyiahf/vczjk/hy0;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/z9a;->typeName:Llyiahf/vczjk/qt5;

    new-instance p2, Llyiahf/vczjk/hy0;

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p1}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, "Array"

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p1

    iget-object p3, p3, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-direct {p2, p3, p1}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    iput-object p2, p0, Llyiahf/vczjk/z9a;->arrayClassId:Llyiahf/vczjk/hy0;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/z9a;
    .locals 1

    const-class v0, Llyiahf/vczjk/z9a;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/z9a;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/z9a;
    .locals 1

    sget-object v0, Llyiahf/vczjk/z9a;->OooOOO0:[Llyiahf/vczjk/z9a;

    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/z9a;

    return-object v0
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/hy0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z9a;->arrayClassId:Llyiahf/vczjk/hy0;

    return-object v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/hy0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z9a;->classId:Llyiahf/vczjk/hy0;

    return-object v0
.end method

.method public final OooO0OO()Llyiahf/vczjk/qt5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z9a;->typeName:Llyiahf/vczjk/qt5;

    return-object v0
.end method
