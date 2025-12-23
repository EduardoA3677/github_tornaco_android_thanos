.class public abstract Llyiahf/vczjk/z56;
.super Llyiahf/vczjk/wt9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xo1;


# instance fields
.field protected final _isInt:Z

.field protected final _numberType:Llyiahf/vczjk/db4;

.field protected final _schemaType:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/Class;Llyiahf/vczjk/db4;Ljava/lang/String;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/wt9;-><init>(Ljava/lang/Class;)V

    iput-object p2, p0, Llyiahf/vczjk/z56;->_numberType:Llyiahf/vczjk/db4;

    iput-object p3, p0, Llyiahf/vczjk/z56;->_schemaType:Ljava/lang/String;

    sget-object p1, Llyiahf/vczjk/db4;->OooOOO0:Llyiahf/vczjk/db4;

    if-eq p2, p1, :cond_1

    sget-object p1, Llyiahf/vczjk/db4;->OooOOO:Llyiahf/vczjk/db4;

    if-eq p2, p1, :cond_1

    sget-object p1, Llyiahf/vczjk/db4;->OooOOOO:Llyiahf/vczjk/db4;

    if-ne p2, p1, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    goto :goto_1

    :cond_1
    :goto_0
    const/4 p1, 0x1

    :goto_1
    iput-boolean p1, p0, Llyiahf/vczjk/z56;->_isInt:Z

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    invoke-static {p1, p2, v0}, Llyiahf/vczjk/b59;->OooOO0O(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;Ljava/lang/Class;)Llyiahf/vczjk/q94;

    move-result-object p1

    if-eqz p1, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/q94;->OooO0o()Llyiahf/vczjk/p94;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    const/16 p2, 0x8

    if-eq p1, p2, :cond_0

    goto :goto_0

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    const-class p2, Ljava/math/BigDecimal;

    if-ne p1, p2, :cond_1

    sget-object p1, Llyiahf/vczjk/y56;->OooOOOO:Llyiahf/vczjk/y56;

    sget-object p1, Llyiahf/vczjk/x56;->OooOOOo:Llyiahf/vczjk/x56;

    return-object p1

    :cond_1
    sget-object p1, Llyiahf/vczjk/x56;->OooOOo0:Llyiahf/vczjk/x56;

    return-object p1

    :cond_2
    :goto_0
    return-object p0
.end method
