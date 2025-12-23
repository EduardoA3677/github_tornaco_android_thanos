.class public final enum Llyiahf/vczjk/ww;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/ww;

.field public static final enum OooOOO0:Llyiahf/vczjk/ww;

.field public static final synthetic OooOOOO:[Llyiahf/vczjk/ww;


# instance fields
.field private final prefValue:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/ww;

    const-string v1, "thanox"

    const-string v2, "BasedOnXposed"

    const/4 v3, 0x0

    invoke-direct {v0, v2, v3, v1}, Llyiahf/vczjk/ww;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/ww;->OooOOO0:Llyiahf/vczjk/ww;

    new-instance v1, Llyiahf/vczjk/ww;

    const-string v2, "thanos"

    const-string v3, "BasedOnShizuku"

    const/4 v4, 0x1

    invoke-direct {v1, v3, v4, v2}, Llyiahf/vczjk/ww;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    sput-object v1, Llyiahf/vczjk/ww;->OooOOO:Llyiahf/vczjk/ww;

    new-instance v2, Llyiahf/vczjk/ww;

    const-string v3, "ask"

    const-string v4, "Ask"

    const/4 v5, 0x2

    invoke-direct {v2, v4, v5, v3}, Llyiahf/vczjk/ww;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    filled-new-array {v0, v1, v2}, [Llyiahf/vczjk/ww;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/ww;->OooOOOO:[Llyiahf/vczjk/ww;

    invoke-static {v0}, Llyiahf/vczjk/yi4;->OoooO0([Ljava/lang/Enum;)Llyiahf/vczjk/np2;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    iput-object p3, p0, Llyiahf/vczjk/ww;->prefValue:Ljava/lang/String;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/ww;
    .locals 1

    const-class v0, Llyiahf/vczjk/ww;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/ww;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/ww;
    .locals 1

    sget-object v0, Llyiahf/vczjk/ww;->OooOOOO:[Llyiahf/vczjk/ww;

    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/ww;

    return-object v0
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ww;->prefValue:Ljava/lang/String;

    return-object v0
.end method
