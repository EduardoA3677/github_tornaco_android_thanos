.class public enum Llyiahf/vczjk/sy8;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/sy8;

.field public static final enum OooOOO0:Llyiahf/vczjk/sy8;

.field public static final enum OooOOOO:Llyiahf/vczjk/sy8;

.field public static final enum OooOOOo:Llyiahf/vczjk/ry8;

.field public static final synthetic OooOOo0:[Llyiahf/vczjk/sy8;


# instance fields
.field private final defaultValue:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 10

    const/4 v0, 0x3

    new-instance v1, Llyiahf/vczjk/sy8;

    const-string v2, "NULL"

    const/4 v3, 0x0

    const/4 v4, 0x0

    invoke-direct {v1, v2, v3, v4}, Llyiahf/vczjk/sy8;-><init>(Ljava/lang/String;ILjava/lang/Object;)V

    sput-object v1, Llyiahf/vczjk/sy8;->OooOOO0:Llyiahf/vczjk/sy8;

    new-instance v2, Llyiahf/vczjk/sy8;

    const/4 v5, -0x1

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    const-string v6, "INDEX"

    const/4 v7, 0x1

    invoke-direct {v2, v6, v7, v5}, Llyiahf/vczjk/sy8;-><init>(Ljava/lang/String;ILjava/lang/Object;)V

    sput-object v2, Llyiahf/vczjk/sy8;->OooOOO:Llyiahf/vczjk/sy8;

    new-instance v5, Llyiahf/vczjk/sy8;

    sget-object v6, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    const-string v8, "FALSE"

    const/4 v9, 0x2

    invoke-direct {v5, v8, v9, v6}, Llyiahf/vczjk/sy8;-><init>(Ljava/lang/String;ILjava/lang/Object;)V

    sput-object v5, Llyiahf/vczjk/sy8;->OooOOOO:Llyiahf/vczjk/sy8;

    new-instance v6, Llyiahf/vczjk/ry8;

    const-string v8, "MAP_GET_OR_DEFAULT"

    invoke-direct {v6, v8, v0, v4}, Llyiahf/vczjk/sy8;-><init>(Ljava/lang/String;ILjava/lang/Object;)V

    sput-object v6, Llyiahf/vczjk/sy8;->OooOOOo:Llyiahf/vczjk/ry8;

    const/4 v4, 0x4

    new-array v4, v4, [Llyiahf/vczjk/sy8;

    aput-object v1, v4, v3

    aput-object v2, v4, v7

    aput-object v5, v4, v9

    aput-object v6, v4, v0

    sput-object v4, Llyiahf/vczjk/sy8;->OooOOo0:[Llyiahf/vczjk/sy8;

    invoke-static {v4}, Llyiahf/vczjk/yi4;->OoooO0([Ljava/lang/Enum;)Llyiahf/vczjk/np2;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/Object;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    iput-object p3, p0, Llyiahf/vczjk/sy8;->defaultValue:Ljava/lang/Object;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/sy8;
    .locals 1

    const-class v0, Llyiahf/vczjk/sy8;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/sy8;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/sy8;
    .locals 1

    sget-object v0, Llyiahf/vczjk/sy8;->OooOOo0:[Llyiahf/vczjk/sy8;

    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/sy8;

    return-object v0
.end method
