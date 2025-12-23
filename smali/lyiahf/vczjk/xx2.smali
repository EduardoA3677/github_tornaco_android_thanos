.class public final enum Llyiahf/vczjk/xx2;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/xx2;

.field public static final enum OooOOO0:Llyiahf/vczjk/xx2;

.field public static final enum OooOOOO:Llyiahf/vczjk/xx2;

.field public static final enum OooOOOo:Llyiahf/vczjk/xx2;

.field public static final synthetic OooOOo0:[Llyiahf/vczjk/xx2;


# instance fields
.field private final isList:Z


# direct methods
.method static constructor <clinit>()V
    .locals 7

    new-instance v0, Llyiahf/vczjk/xx2;

    const-string v1, "SCALAR"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2, v2}, Llyiahf/vczjk/xx2;-><init>(Ljava/lang/String;IZ)V

    sput-object v0, Llyiahf/vczjk/xx2;->OooOOO0:Llyiahf/vczjk/xx2;

    new-instance v1, Llyiahf/vczjk/xx2;

    const-string v3, "VECTOR"

    const/4 v4, 0x1

    invoke-direct {v1, v3, v4, v4}, Llyiahf/vczjk/xx2;-><init>(Ljava/lang/String;IZ)V

    sput-object v1, Llyiahf/vczjk/xx2;->OooOOO:Llyiahf/vczjk/xx2;

    new-instance v3, Llyiahf/vczjk/xx2;

    const-string v5, "PACKED_VECTOR"

    const/4 v6, 0x2

    invoke-direct {v3, v5, v6, v4}, Llyiahf/vczjk/xx2;-><init>(Ljava/lang/String;IZ)V

    sput-object v3, Llyiahf/vczjk/xx2;->OooOOOO:Llyiahf/vczjk/xx2;

    new-instance v4, Llyiahf/vczjk/xx2;

    const-string v5, "MAP"

    const/4 v6, 0x3

    invoke-direct {v4, v5, v6, v2}, Llyiahf/vczjk/xx2;-><init>(Ljava/lang/String;IZ)V

    sput-object v4, Llyiahf/vczjk/xx2;->OooOOOo:Llyiahf/vczjk/xx2;

    filled-new-array {v0, v1, v3, v4}, [Llyiahf/vczjk/xx2;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/xx2;->OooOOo0:[Llyiahf/vczjk/xx2;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;IZ)V
    .locals 0

    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    iput-boolean p3, p0, Llyiahf/vczjk/xx2;->isList:Z

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/xx2;
    .locals 1

    const-class v0, Llyiahf/vczjk/xx2;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/xx2;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/xx2;
    .locals 1

    sget-object v0, Llyiahf/vczjk/xx2;->OooOOo0:[Llyiahf/vczjk/xx2;

    invoke-virtual {v0}, [Llyiahf/vczjk/xx2;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/xx2;

    return-object v0
.end method
