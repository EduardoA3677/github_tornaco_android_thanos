.class public final Llyiahf/vczjk/fka;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/gka;
.implements Ljava/io/Serializable;


# static fields
.field public static final OooOOO0:Llyiahf/vczjk/fka;

.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _creatorMinLevel:Llyiahf/vczjk/x84;

.field protected final _fieldMinLevel:Llyiahf/vczjk/x84;

.field protected final _getterMinLevel:Llyiahf/vczjk/x84;

.field protected final _isGetterMinLevel:Llyiahf/vczjk/x84;

.field protected final _setterMinLevel:Llyiahf/vczjk/x84;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/fka;

    sget-object v1, Llyiahf/vczjk/x84;->OooOOO:Llyiahf/vczjk/x84;

    sget-object v3, Llyiahf/vczjk/x84;->OooOOO0:Llyiahf/vczjk/x84;

    move-object v2, v1

    move-object v4, v3

    move-object v5, v1

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/fka;-><init>(Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;)V

    sput-object v0, Llyiahf/vczjk/fka;->OooOOO0:Llyiahf/vczjk/fka;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;Llyiahf/vczjk/x84;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fka;->_getterMinLevel:Llyiahf/vczjk/x84;

    iput-object p2, p0, Llyiahf/vczjk/fka;->_isGetterMinLevel:Llyiahf/vczjk/x84;

    iput-object p3, p0, Llyiahf/vczjk/fka;->_setterMinLevel:Llyiahf/vczjk/x84;

    iput-object p4, p0, Llyiahf/vczjk/fka;->_creatorMinLevel:Llyiahf/vczjk/x84;

    iput-object p5, p0, Llyiahf/vczjk/fka;->_fieldMinLevel:Llyiahf/vczjk/x84;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/gn;)Z
    .locals 1

    invoke-virtual {p1}, Llyiahf/vczjk/pm;->o0ooOO0()Ljava/lang/reflect/Member;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/fka;->_creatorMinLevel:Llyiahf/vczjk/x84;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x84;->OooO00o(Ljava/lang/reflect/Member;)Z

    move-result p1

    return p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/fka;->_getterMinLevel:Llyiahf/vczjk/x84;

    iget-object v1, p0, Llyiahf/vczjk/fka;->_isGetterMinLevel:Llyiahf/vczjk/x84;

    iget-object v2, p0, Llyiahf/vczjk/fka;->_setterMinLevel:Llyiahf/vczjk/x84;

    iget-object v3, p0, Llyiahf/vczjk/fka;->_creatorMinLevel:Llyiahf/vczjk/x84;

    iget-object v4, p0, Llyiahf/vczjk/fka;->_fieldMinLevel:Llyiahf/vczjk/x84;

    new-instance v5, Ljava/lang/StringBuilder;

    const-string v6, "[Visibility: getter="

    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, ",isGetter="

    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, ",setter="

    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, ",creator="

    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, ",field="

    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, "]"

    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
