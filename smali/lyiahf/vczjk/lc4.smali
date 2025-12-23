.class public final enum Llyiahf/vczjk/lc4;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/lc4;

.field public static final enum OooOOO0:Llyiahf/vczjk/lc4;

.field public static final enum OooOOOO:Llyiahf/vczjk/lc4;

.field public static final synthetic OooOOOo:[Llyiahf/vczjk/lc4;


# instance fields
.field private final _defaultPropertyName:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    new-instance v0, Llyiahf/vczjk/lc4;

    const-string v1, "NONE"

    const/4 v2, 0x0

    const/4 v3, 0x0

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/lc4;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/lc4;->OooOOO0:Llyiahf/vczjk/lc4;

    new-instance v1, Llyiahf/vczjk/lc4;

    const-string v2, "@class"

    const-string v4, "CLASS"

    const/4 v5, 0x1

    invoke-direct {v1, v4, v5, v2}, Llyiahf/vczjk/lc4;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    sput-object v1, Llyiahf/vczjk/lc4;->OooOOO:Llyiahf/vczjk/lc4;

    new-instance v2, Llyiahf/vczjk/lc4;

    const-string v4, "@c"

    const-string v5, "MINIMAL_CLASS"

    const/4 v6, 0x2

    invoke-direct {v2, v5, v6, v4}, Llyiahf/vczjk/lc4;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    sput-object v2, Llyiahf/vczjk/lc4;->OooOOOO:Llyiahf/vczjk/lc4;

    new-instance v4, Llyiahf/vczjk/lc4;

    const-string v5, "@type"

    const-string v6, "NAME"

    const/4 v7, 0x3

    invoke-direct {v4, v6, v7, v5}, Llyiahf/vczjk/lc4;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    new-instance v5, Llyiahf/vczjk/lc4;

    const-string v6, "CUSTOM"

    const/4 v7, 0x4

    invoke-direct {v5, v6, v7, v3}, Llyiahf/vczjk/lc4;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    filled-new-array {v0, v1, v2, v4, v5}, [Llyiahf/vczjk/lc4;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/lc4;->OooOOOo:[Llyiahf/vczjk/lc4;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    iput-object p3, p0, Llyiahf/vczjk/lc4;->_defaultPropertyName:Ljava/lang/String;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/lc4;
    .locals 1

    const-class v0, Llyiahf/vczjk/lc4;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/lc4;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/lc4;
    .locals 1

    sget-object v0, Llyiahf/vczjk/lc4;->OooOOOo:[Llyiahf/vczjk/lc4;

    invoke-virtual {v0}, [Llyiahf/vczjk/lc4;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/lc4;

    return-object v0
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/lc4;->_defaultPropertyName:Ljava/lang/String;

    return-object v0
.end method
