.class public final Llyiahf/vczjk/wa7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/wa7;

.field public static final OooOOOO:Llyiahf/vczjk/wa7;

.field public static final OooOOOo:Llyiahf/vczjk/wa7;

.field private static final serialVersionUID:J = -0x1L


# instance fields
.field public final transient OooOOO0:Llyiahf/vczjk/pc0;

.field protected _contentNulls:Llyiahf/vczjk/d56;

.field protected final _defaultValue:Ljava/lang/String;

.field protected final _description:Ljava/lang/String;

.field protected final _index:Ljava/lang/Integer;

.field protected final _required:Ljava/lang/Boolean;

.field protected _valueNulls:Llyiahf/vczjk/d56;


# direct methods
.method static constructor <clinit>()V
    .locals 10

    new-instance v0, Llyiahf/vczjk/wa7;

    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/wa7;-><init>(Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/pc0;Llyiahf/vczjk/d56;Llyiahf/vczjk/d56;)V

    sput-object v0, Llyiahf/vczjk/wa7;->OooOOO:Llyiahf/vczjk/wa7;

    new-instance v1, Llyiahf/vczjk/wa7;

    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    const/4 v8, 0x0

    invoke-direct/range {v1 .. v8}, Llyiahf/vczjk/wa7;-><init>(Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/pc0;Llyiahf/vczjk/d56;Llyiahf/vczjk/d56;)V

    sput-object v1, Llyiahf/vczjk/wa7;->OooOOOO:Llyiahf/vczjk/wa7;

    new-instance v2, Llyiahf/vczjk/wa7;

    const/4 v9, 0x0

    invoke-direct/range {v2 .. v9}, Llyiahf/vczjk/wa7;-><init>(Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/pc0;Llyiahf/vczjk/d56;Llyiahf/vczjk/d56;)V

    sput-object v2, Llyiahf/vczjk/wa7;->OooOOOo:Llyiahf/vczjk/wa7;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/pc0;Llyiahf/vczjk/d56;Llyiahf/vczjk/d56;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/wa7;->_required:Ljava/lang/Boolean;

    iput-object p2, p0, Llyiahf/vczjk/wa7;->_description:Ljava/lang/String;

    iput-object p3, p0, Llyiahf/vczjk/wa7;->_index:Ljava/lang/Integer;

    if-eqz p4, :cond_0

    invoke-virtual {p4}, Ljava/lang/String;->isEmpty()Z

    move-result p1

    if-eqz p1, :cond_1

    :cond_0
    const/4 p4, 0x0

    :cond_1
    iput-object p4, p0, Llyiahf/vczjk/wa7;->_defaultValue:Ljava/lang/String;

    iput-object p5, p0, Llyiahf/vczjk/wa7;->OooOOO0:Llyiahf/vczjk/pc0;

    iput-object p6, p0, Llyiahf/vczjk/wa7;->_valueNulls:Llyiahf/vczjk/d56;

    iput-object p7, p0, Llyiahf/vczjk/wa7;->_contentNulls:Llyiahf/vczjk/d56;

    return-void
.end method

.method public static OooO00o(Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;)Llyiahf/vczjk/wa7;
    .locals 8

    if-nez p1, :cond_3

    if-nez p2, :cond_3

    if-eqz p3, :cond_0

    goto :goto_0

    :cond_0
    if-nez p0, :cond_1

    sget-object p0, Llyiahf/vczjk/wa7;->OooOOOo:Llyiahf/vczjk/wa7;

    return-object p0

    :cond_1
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p0

    if-eqz p0, :cond_2

    sget-object p0, Llyiahf/vczjk/wa7;->OooOOO:Llyiahf/vczjk/wa7;

    return-object p0

    :cond_2
    sget-object p0, Llyiahf/vczjk/wa7;->OooOOOO:Llyiahf/vczjk/wa7;

    return-object p0

    :cond_3
    :goto_0
    new-instance v0, Llyiahf/vczjk/wa7;

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v5, 0x0

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/wa7;-><init>(Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/pc0;Llyiahf/vczjk/d56;Llyiahf/vczjk/d56;)V

    return-object v0
.end method


# virtual methods
.method public final OooO0O0()Llyiahf/vczjk/d56;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wa7;->_contentNulls:Llyiahf/vczjk/d56;

    return-object v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/pc0;)Llyiahf/vczjk/wa7;
    .locals 8

    new-instance v0, Llyiahf/vczjk/wa7;

    iget-object v1, p0, Llyiahf/vczjk/wa7;->_required:Ljava/lang/Boolean;

    iget-object v2, p0, Llyiahf/vczjk/wa7;->_description:Ljava/lang/String;

    iget-object v3, p0, Llyiahf/vczjk/wa7;->_index:Ljava/lang/Integer;

    iget-object v4, p0, Llyiahf/vczjk/wa7;->_defaultValue:Ljava/lang/String;

    iget-object v6, p0, Llyiahf/vczjk/wa7;->_valueNulls:Llyiahf/vczjk/d56;

    iget-object v7, p0, Llyiahf/vczjk/wa7;->_contentNulls:Llyiahf/vczjk/d56;

    move-object v5, p1

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/wa7;-><init>(Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/pc0;Llyiahf/vczjk/d56;Llyiahf/vczjk/d56;)V

    return-object v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/d56;Llyiahf/vczjk/d56;)Llyiahf/vczjk/wa7;
    .locals 8

    new-instance v0, Llyiahf/vczjk/wa7;

    iget-object v1, p0, Llyiahf/vczjk/wa7;->_required:Ljava/lang/Boolean;

    iget-object v2, p0, Llyiahf/vczjk/wa7;->_description:Ljava/lang/String;

    iget-object v3, p0, Llyiahf/vczjk/wa7;->_index:Ljava/lang/Integer;

    iget-object v4, p0, Llyiahf/vczjk/wa7;->_defaultValue:Ljava/lang/String;

    iget-object v5, p0, Llyiahf/vczjk/wa7;->OooOOO0:Llyiahf/vczjk/pc0;

    move-object v6, p1

    move-object v7, p2

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/wa7;-><init>(Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/pc0;Llyiahf/vczjk/d56;Llyiahf/vczjk/d56;)V

    return-object v0
.end method

.method public readResolve()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wa7;->_description:Ljava/lang/String;

    if-nez v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/wa7;->_index:Ljava/lang/Integer;

    if-nez v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/wa7;->_defaultValue:Ljava/lang/String;

    if-nez v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/wa7;->OooOOO0:Llyiahf/vczjk/pc0;

    if-nez v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/wa7;->_valueNulls:Llyiahf/vczjk/d56;

    if-nez v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/wa7;->_contentNulls:Llyiahf/vczjk/d56;

    if-nez v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/wa7;->_required:Ljava/lang/Boolean;

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/wa7;->OooOOOo:Llyiahf/vczjk/wa7;

    return-object v0

    :cond_0
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_1

    sget-object v0, Llyiahf/vczjk/wa7;->OooOOO:Llyiahf/vczjk/wa7;

    return-object v0

    :cond_1
    sget-object v0, Llyiahf/vczjk/wa7;->OooOOOO:Llyiahf/vczjk/wa7;

    return-object v0

    :cond_2
    return-object p0
.end method
