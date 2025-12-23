.class public final enum Llyiahf/vczjk/us9;
.super Llyiahf/vczjk/xs9;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "LAZILY_PARSED_NUMBER"

    const/4 v1, 0x1

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/qb4;)Ljava/lang/Number;
    .locals 1

    new-instance v0, Llyiahf/vczjk/jp4;

    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->o00000oO()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Llyiahf/vczjk/jp4;-><init>(Ljava/lang/String;)V

    return-object v0
.end method
