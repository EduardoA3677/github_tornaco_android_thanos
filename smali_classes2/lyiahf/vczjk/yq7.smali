.class public final enum Llyiahf/vczjk/yq7;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/yq7;

.field public static final enum OooOOO0:Llyiahf/vczjk/yq7;

.field public static final enum OooOOOO:Llyiahf/vczjk/yq7;

.field public static final synthetic OooOOOo:[Llyiahf/vczjk/yq7;


# instance fields
.field private final description:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/yq7;

    const-string v1, "ignore"

    const-string v2, "IGNORE"

    const/4 v3, 0x0

    invoke-direct {v0, v2, v3, v1}, Llyiahf/vczjk/yq7;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/yq7;->OooOOO0:Llyiahf/vczjk/yq7;

    new-instance v1, Llyiahf/vczjk/yq7;

    const-string v2, "warn"

    const-string v3, "WARN"

    const/4 v4, 0x1

    invoke-direct {v1, v3, v4, v2}, Llyiahf/vczjk/yq7;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    sput-object v1, Llyiahf/vczjk/yq7;->OooOOO:Llyiahf/vczjk/yq7;

    new-instance v2, Llyiahf/vczjk/yq7;

    const-string v3, "strict"

    const-string v4, "STRICT"

    const/4 v5, 0x2

    invoke-direct {v2, v4, v5, v3}, Llyiahf/vczjk/yq7;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    sput-object v2, Llyiahf/vczjk/yq7;->OooOOOO:Llyiahf/vczjk/yq7;

    filled-new-array {v0, v1, v2}, [Llyiahf/vczjk/yq7;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/yq7;->OooOOOo:[Llyiahf/vczjk/yq7;

    invoke-static {v0}, Llyiahf/vczjk/yi4;->OoooO0([Ljava/lang/Enum;)Llyiahf/vczjk/np2;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    iput-object p3, p0, Llyiahf/vczjk/yq7;->description:Ljava/lang/String;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/yq7;
    .locals 1

    const-class v0, Llyiahf/vczjk/yq7;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/yq7;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/yq7;
    .locals 1

    sget-object v0, Llyiahf/vczjk/yq7;->OooOOOo:[Llyiahf/vczjk/yq7;

    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/yq7;

    return-object v0
.end method


# virtual methods
.method public final getDescription()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/yq7;->description:Ljava/lang/String;

    return-object v0
.end method
