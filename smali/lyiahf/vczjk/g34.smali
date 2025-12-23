.class public abstract Llyiahf/vczjk/g34;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/la4;

.field public static final OooO0O0:Llyiahf/vczjk/m76;

.field public static final OooO0OO:Llyiahf/vczjk/i76;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/la4;

    new-instance v1, Llyiahf/vczjk/l94;

    const/4 v2, 0x0

    invoke-direct {v1, v2}, Llyiahf/vczjk/l94;-><init>(Llyiahf/vczjk/e76;)V

    invoke-direct {v0, v1}, Llyiahf/vczjk/e76;-><init>(Llyiahf/vczjk/l94;)V

    sput-object v0, Llyiahf/vczjk/g34;->OooO00o:Llyiahf/vczjk/la4;

    invoke-virtual {v0}, Llyiahf/vczjk/e76;->OooO0oO()Llyiahf/vczjk/m76;

    move-result-object v1

    sput-object v1, Llyiahf/vczjk/g34;->OooO0O0:Llyiahf/vczjk/m76;

    invoke-virtual {v0}, Llyiahf/vczjk/e76;->OooO0oO()Llyiahf/vczjk/m76;

    move-result-object v1

    iget-object v2, v1, Llyiahf/vczjk/m76;->_config:Llyiahf/vczjk/gg8;

    iget-object v2, v2, Llyiahf/vczjk/gg8;->_defaultPrettyPrinter:Llyiahf/vczjk/u37;

    iget-object v3, v1, Llyiahf/vczjk/m76;->_generatorSettings:Llyiahf/vczjk/k76;

    if-nez v2, :cond_0

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v2, Llyiahf/vczjk/m76;->OooOOO0:Llyiahf/vczjk/ij5;

    :cond_0
    iget-object v4, v3, Llyiahf/vczjk/k76;->prettyPrinter:Llyiahf/vczjk/u37;

    if-ne v2, v4, :cond_1

    goto :goto_0

    :cond_1
    new-instance v4, Llyiahf/vczjk/k76;

    iget-object v3, v3, Llyiahf/vczjk/k76;->rootValueSeparator:Llyiahf/vczjk/fg8;

    invoke-direct {v4, v2, v3}, Llyiahf/vczjk/k76;-><init>(Llyiahf/vczjk/u37;Llyiahf/vczjk/fg8;)V

    move-object v3, v4

    :goto_0
    iget-object v2, v1, Llyiahf/vczjk/m76;->_prefetch:Llyiahf/vczjk/l76;

    iget-object v4, v1, Llyiahf/vczjk/m76;->_generatorSettings:Llyiahf/vczjk/k76;

    if-ne v4, v3, :cond_2

    goto :goto_1

    :cond_2
    new-instance v4, Llyiahf/vczjk/m76;

    iget-object v5, v1, Llyiahf/vczjk/m76;->_config:Llyiahf/vczjk/gg8;

    invoke-direct {v4, v1, v5, v3, v2}, Llyiahf/vczjk/m76;-><init>(Llyiahf/vczjk/m76;Llyiahf/vczjk/gg8;Llyiahf/vczjk/k76;Llyiahf/vczjk/l76;)V

    :goto_1
    iget-object v1, v0, Llyiahf/vczjk/e76;->_deserializationConfig:Llyiahf/vczjk/t72;

    iget-object v2, v0, Llyiahf/vczjk/e76;->_typeFactory:Llyiahf/vczjk/a4a;

    const-class v3, Llyiahf/vczjk/qa4;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/a4a;->OooOO0O(Ljava/lang/reflect/Type;)Llyiahf/vczjk/x64;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/i76;

    invoke-direct {v3, v0, v1, v2}, Llyiahf/vczjk/i76;-><init>(Llyiahf/vczjk/e76;Llyiahf/vczjk/t72;Llyiahf/vczjk/x64;)V

    sput-object v3, Llyiahf/vczjk/g34;->OooO0OO:Llyiahf/vczjk/i76;

    return-void
.end method
