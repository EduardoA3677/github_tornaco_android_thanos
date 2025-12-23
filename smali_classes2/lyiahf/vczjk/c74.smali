.class public final Llyiahf/vczjk/c74;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0OO:Llyiahf/vczjk/c74;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ad4;

.field public final OooO0O0:Z


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/c74;

    sget-object v1, Llyiahf/vczjk/p64;->OooO00o:Llyiahf/vczjk/hc3;

    sget-object v1, Llyiahf/vczjk/bl4;->OooOOo0:Llyiahf/vczjk/bl4;

    const-string v2, "configuredKotlinVersion"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v2, Llyiahf/vczjk/p64;->OooO0Oo:Llyiahf/vczjk/q64;

    iget-object v3, v2, Llyiahf/vczjk/q64;->OooO0O0:Llyiahf/vczjk/bl4;

    if-eqz v3, :cond_0

    iget v3, v3, Llyiahf/vczjk/bl4;->OooOOOo:I

    iget v1, v1, Llyiahf/vczjk/bl4;->OooOOOo:I

    sub-int/2addr v3, v1

    if-gtz v3, :cond_0

    iget-object v1, v2, Llyiahf/vczjk/q64;->OooO0OO:Llyiahf/vczjk/yq7;

    goto :goto_0

    :cond_0
    iget-object v1, v2, Llyiahf/vczjk/q64;->OooO00o:Llyiahf/vczjk/yq7;

    :goto_0
    const-string v2, "globalReportLevel"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v2, Llyiahf/vczjk/yq7;->OooOOO:Llyiahf/vczjk/yq7;

    if-ne v1, v2, :cond_1

    const/4 v2, 0x0

    goto :goto_1

    :cond_1
    move-object v2, v1

    :goto_1
    new-instance v3, Llyiahf/vczjk/ad4;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/ad4;-><init>(Llyiahf/vczjk/yq7;Llyiahf/vczjk/yq7;)V

    sget-object v1, Llyiahf/vczjk/b74;->OooOOO:Llyiahf/vczjk/b74;

    invoke-direct {v0, v3}, Llyiahf/vczjk/c74;-><init>(Llyiahf/vczjk/ad4;)V

    sput-object v0, Llyiahf/vczjk/c74;->OooO0OO:Llyiahf/vczjk/c74;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ad4;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/b74;->OooOOO:Llyiahf/vczjk/b74;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/c74;->OooO00o:Llyiahf/vczjk/ad4;

    iget-boolean p1, p1, Llyiahf/vczjk/ad4;->OooO0Oo:Z

    if-nez p1, :cond_1

    sget-object p1, Llyiahf/vczjk/p64;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/b74;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/yq7;->OooOOO0:Llyiahf/vczjk/yq7;

    if-ne p1, v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    goto :goto_1

    :cond_1
    :goto_0
    const/4 p1, 0x1

    :goto_1
    iput-boolean p1, p0, Llyiahf/vczjk/c74;->OooO0O0:Z

    return-void
.end method


# virtual methods
.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "JavaTypeEnhancementState(jsr305="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/c74;->OooO00o:Llyiahf/vczjk/ad4;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", getReportLevelForAnnotation="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    sget-object v1, Llyiahf/vczjk/b74;->OooOOO:Llyiahf/vczjk/b74;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
