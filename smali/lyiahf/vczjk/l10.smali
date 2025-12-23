.class public final Llyiahf/vczjk/l10;
.super Llyiahf/vczjk/rja;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _attrName:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Llyiahf/vczjk/bo8;Llyiahf/vczjk/lo;Llyiahf/vczjk/x64;)V
    .locals 11

    sget-object v0, Llyiahf/vczjk/ea4;->OooOOo0:Llyiahf/vczjk/ea4;

    sget-object v2, Llyiahf/vczjk/ea4;->OooOOO0:Llyiahf/vczjk/ea4;

    iget-object v3, p2, Llyiahf/vczjk/bo8;->OooOOo:Llyiahf/vczjk/fa4;

    const/4 v4, 0x0

    if-nez v3, :cond_1

    :cond_0
    :goto_0
    move v8, v4

    goto :goto_1

    :cond_1
    invoke-virtual {v3}, Llyiahf/vczjk/fa4;->OooO0OO()Llyiahf/vczjk/ea4;

    move-result-object v5

    if-eq v5, v2, :cond_0

    if-eq v5, v0, :cond_0

    const/4 v4, 0x1

    goto :goto_0

    :goto_1
    if-nez v3, :cond_2

    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    :goto_2
    move-object v9, v0

    goto :goto_4

    :cond_2
    invoke-virtual {v3}, Llyiahf/vczjk/fa4;->OooO0OO()Llyiahf/vczjk/ea4;

    move-result-object v3

    if-eq v3, v2, :cond_4

    sget-object v2, Llyiahf/vczjk/ea4;->OooOOO:Llyiahf/vczjk/ea4;

    if-eq v3, v2, :cond_4

    if-ne v3, v0, :cond_3

    goto :goto_3

    :cond_3
    sget-object v0, Llyiahf/vczjk/ea4;->OooOOOO:Llyiahf/vczjk/ea4;

    goto :goto_2

    :cond_4
    :goto_3
    const/4 v0, 0x0

    goto :goto_2

    :goto_4
    const/4 v5, 0x0

    const/4 v6, 0x0

    iget-object v2, p2, Llyiahf/vczjk/bo8;->OooOOOO:Llyiahf/vczjk/pm;

    const/4 v7, 0x0

    const/4 v10, 0x0

    move-object v0, p0

    move-object v1, p2

    move-object v3, p3

    move-object v4, p4

    invoke-direct/range {v0 .. v10}, Llyiahf/vczjk/gb0;-><init>(Llyiahf/vczjk/eb0;Llyiahf/vczjk/pm;Llyiahf/vczjk/lo;Llyiahf/vczjk/x64;Llyiahf/vczjk/zb4;Llyiahf/vczjk/e5a;Llyiahf/vczjk/x64;ZLjava/lang/Object;[Ljava/lang/Class;)V

    iput-object p1, p0, Llyiahf/vczjk/l10;->_attrName:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final OooOOO(Llyiahf/vczjk/tg8;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/l10;->_attrName:Ljava/lang/String;

    iget-object p1, p1, Llyiahf/vczjk/tg8;->OooOo:Llyiahf/vczjk/jn1;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/jn1;->OooO00o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
