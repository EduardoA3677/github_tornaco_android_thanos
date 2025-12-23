.class public final Llyiahf/vczjk/j32;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/u37;
.implements Llyiahf/vczjk/l14;
.implements Ljava/io/Serializable;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/ng8;

.field private static final serialVersionUID:J = 0x1L


# instance fields
.field public transient OooOOO0:I

.field protected _arrayIndenter:Llyiahf/vczjk/h32;

.field protected _objectFieldValueSeparatorWithSpaces:Ljava/lang/String;

.field protected _objectIndenter:Llyiahf/vczjk/h32;

.field protected final _rootSeparator:Llyiahf/vczjk/fg8;

.field protected _separators:Llyiahf/vczjk/rf8;

.field protected _spacesInObjectEntries:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/ng8;

    const-string v1, " "

    invoke-direct {v0, v1}, Llyiahf/vczjk/ng8;-><init>(Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/j32;->OooOOO:Llyiahf/vczjk/ng8;

    return-void
.end method

.method public constructor <init>()V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object v0, Llyiahf/vczjk/g32;->OooOOO0:Llyiahf/vczjk/g32;

    iput-object v0, p0, Llyiahf/vczjk/j32;->_arrayIndenter:Llyiahf/vczjk/h32;

    sget-object v0, Llyiahf/vczjk/k22;->OooOOO0:Llyiahf/vczjk/k22;

    iput-object v0, p0, Llyiahf/vczjk/j32;->_objectIndenter:Llyiahf/vczjk/h32;

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/j32;->_spacesInObjectEntries:Z

    sget-object v0, Llyiahf/vczjk/j32;->OooOOO:Llyiahf/vczjk/ng8;

    iput-object v0, p0, Llyiahf/vczjk/j32;->_rootSeparator:Llyiahf/vczjk/fg8;

    sget-object v0, Llyiahf/vczjk/u37;->OooO:Llyiahf/vczjk/rf8;

    iput-object v0, p0, Llyiahf/vczjk/j32;->_separators:Llyiahf/vczjk/rf8;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, " "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0}, Llyiahf/vczjk/rf8;->OooO0OO()C

    move-result v0

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/j32;->_objectFieldValueSeparatorWithSpaces:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/j32;)V
    .locals 2

    iget-object v0, p1, Llyiahf/vczjk/j32;->_rootSeparator:Llyiahf/vczjk/fg8;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object v1, Llyiahf/vczjk/g32;->OooOOO0:Llyiahf/vczjk/g32;

    iput-object v1, p0, Llyiahf/vczjk/j32;->_arrayIndenter:Llyiahf/vczjk/h32;

    sget-object v1, Llyiahf/vczjk/k22;->OooOOO0:Llyiahf/vczjk/k22;

    iput-object v1, p0, Llyiahf/vczjk/j32;->_objectIndenter:Llyiahf/vczjk/h32;

    const/4 v1, 0x1

    iput-boolean v1, p0, Llyiahf/vczjk/j32;->_spacesInObjectEntries:Z

    iget-object v1, p1, Llyiahf/vczjk/j32;->_arrayIndenter:Llyiahf/vczjk/h32;

    iput-object v1, p0, Llyiahf/vczjk/j32;->_arrayIndenter:Llyiahf/vczjk/h32;

    iget-object v1, p1, Llyiahf/vczjk/j32;->_objectIndenter:Llyiahf/vczjk/h32;

    iput-object v1, p0, Llyiahf/vczjk/j32;->_objectIndenter:Llyiahf/vczjk/h32;

    iget-boolean v1, p1, Llyiahf/vczjk/j32;->_spacesInObjectEntries:Z

    iput-boolean v1, p0, Llyiahf/vczjk/j32;->_spacesInObjectEntries:Z

    iget v1, p1, Llyiahf/vczjk/j32;->OooOOO0:I

    iput v1, p0, Llyiahf/vczjk/j32;->OooOOO0:I

    iget-object v1, p1, Llyiahf/vczjk/j32;->_separators:Llyiahf/vczjk/rf8;

    iput-object v1, p0, Llyiahf/vczjk/j32;->_separators:Llyiahf/vczjk/rf8;

    iget-object p1, p1, Llyiahf/vczjk/j32;->_objectFieldValueSeparatorWithSpaces:Ljava/lang/String;

    iput-object p1, p0, Llyiahf/vczjk/j32;->_objectFieldValueSeparatorWithSpaces:Ljava/lang/String;

    iput-object v0, p0, Llyiahf/vczjk/j32;->_rootSeparator:Llyiahf/vczjk/fg8;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/v94;)V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/j32;->_spacesInObjectEntries:Z

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/j32;->_objectFieldValueSeparatorWithSpaces:Ljava/lang/String;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u94;->o0000OOO(Ljava/lang/String;)V

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/j32;->_separators:Llyiahf/vczjk/rf8;

    invoke-virtual {v0}, Llyiahf/vczjk/rf8;->OooO0OO()C

    move-result v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u94;->o0000OO(C)V

    return-void
.end method

.method public final OooO00o(Llyiahf/vczjk/u94;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/j32;->_objectIndenter:Llyiahf/vczjk/h32;

    iget v1, p0, Llyiahf/vczjk/j32;->OooOOO0:I

    invoke-interface {v0, p1, v1}, Llyiahf/vczjk/h32;->OooO00o(Llyiahf/vczjk/u94;I)V

    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/v94;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/j32;->_rootSeparator:Llyiahf/vczjk/fg8;

    if-eqz v0, :cond_0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u94;->o0000OOo(Llyiahf/vczjk/fg8;)V

    :cond_0
    return-void
.end method

.method public final OooO0OO(Llyiahf/vczjk/v94;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/j32;->_separators:Llyiahf/vczjk/rf8;

    invoke-virtual {v0}, Llyiahf/vczjk/rf8;->OooO00o()C

    move-result v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u94;->o0000OO(C)V

    iget-object v0, p0, Llyiahf/vczjk/j32;->_arrayIndenter:Llyiahf/vczjk/h32;

    iget v1, p0, Llyiahf/vczjk/j32;->OooOOO0:I

    invoke-interface {v0, p1, v1}, Llyiahf/vczjk/h32;->OooO00o(Llyiahf/vczjk/u94;I)V

    return-void
.end method

.method public final OooO0Oo(Llyiahf/vczjk/v94;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/j32;->_separators:Llyiahf/vczjk/rf8;

    invoke-virtual {v0}, Llyiahf/vczjk/rf8;->OooO0O0()C

    move-result v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u94;->o0000OO(C)V

    iget-object v0, p0, Llyiahf/vczjk/j32;->_objectIndenter:Llyiahf/vczjk/h32;

    iget v1, p0, Llyiahf/vczjk/j32;->OooOOO0:I

    invoke-interface {v0, p1, v1}, Llyiahf/vczjk/h32;->OooO00o(Llyiahf/vczjk/u94;I)V

    return-void
.end method

.method public final OooO0o(Llyiahf/vczjk/v94;)V
    .locals 1

    const/16 v0, 0x7b

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u94;->o0000OO(C)V

    iget-object p1, p0, Llyiahf/vczjk/j32;->_objectIndenter:Llyiahf/vczjk/h32;

    invoke-interface {p1}, Llyiahf/vczjk/h32;->OooO0o()Z

    move-result p1

    if-nez p1, :cond_0

    iget p1, p0, Llyiahf/vczjk/j32;->OooOOO0:I

    add-int/lit8 p1, p1, 0x1

    iput p1, p0, Llyiahf/vczjk/j32;->OooOOO0:I

    :cond_0
    return-void
.end method

.method public final OooO0o0(Llyiahf/vczjk/v94;I)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/j32;->_objectIndenter:Llyiahf/vczjk/h32;

    invoke-interface {v0}, Llyiahf/vczjk/h32;->OooO0o()Z

    move-result v0

    if-nez v0, :cond_0

    iget v0, p0, Llyiahf/vczjk/j32;->OooOOO0:I

    add-int/lit8 v0, v0, -0x1

    iput v0, p0, Llyiahf/vczjk/j32;->OooOOO0:I

    :cond_0
    if-lez p2, :cond_1

    iget-object p2, p0, Llyiahf/vczjk/j32;->_objectIndenter:Llyiahf/vczjk/h32;

    iget v0, p0, Llyiahf/vczjk/j32;->OooOOO0:I

    invoke-interface {p2, p1, v0}, Llyiahf/vczjk/h32;->OooO00o(Llyiahf/vczjk/u94;I)V

    goto :goto_0

    :cond_1
    const/16 p2, 0x20

    invoke-virtual {p1, p2}, Llyiahf/vczjk/u94;->o0000OO(C)V

    :goto_0
    const/16 p2, 0x7d

    invoke-virtual {p1, p2}, Llyiahf/vczjk/u94;->o0000OO(C)V

    return-void
.end method

.method public final OooO0oO(Llyiahf/vczjk/v94;I)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/j32;->_arrayIndenter:Llyiahf/vczjk/h32;

    invoke-interface {v0}, Llyiahf/vczjk/h32;->OooO0o()Z

    move-result v0

    if-nez v0, :cond_0

    iget v0, p0, Llyiahf/vczjk/j32;->OooOOO0:I

    add-int/lit8 v0, v0, -0x1

    iput v0, p0, Llyiahf/vczjk/j32;->OooOOO0:I

    :cond_0
    if-lez p2, :cond_1

    iget-object p2, p0, Llyiahf/vczjk/j32;->_arrayIndenter:Llyiahf/vczjk/h32;

    iget v0, p0, Llyiahf/vczjk/j32;->OooOOO0:I

    invoke-interface {p2, p1, v0}, Llyiahf/vczjk/h32;->OooO00o(Llyiahf/vczjk/u94;I)V

    goto :goto_0

    :cond_1
    const/16 p2, 0x20

    invoke-virtual {p1, p2}, Llyiahf/vczjk/u94;->o0000OO(C)V

    :goto_0
    const/16 p2, 0x5d

    invoke-virtual {p1, p2}, Llyiahf/vczjk/u94;->o0000OO(C)V

    return-void
.end method

.method public final OooO0oo(Llyiahf/vczjk/v94;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/j32;->_arrayIndenter:Llyiahf/vczjk/h32;

    invoke-interface {v0}, Llyiahf/vczjk/h32;->OooO0o()Z

    move-result v0

    if-nez v0, :cond_0

    iget v0, p0, Llyiahf/vczjk/j32;->OooOOO0:I

    add-int/lit8 v0, v0, 0x1

    iput v0, p0, Llyiahf/vczjk/j32;->OooOOO0:I

    :cond_0
    const/16 v0, 0x5b

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u94;->o0000OO(C)V

    return-void
.end method

.method public final OooOO0(Llyiahf/vczjk/v94;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/j32;->_arrayIndenter:Llyiahf/vczjk/h32;

    iget v1, p0, Llyiahf/vczjk/j32;->OooOOO0:I

    invoke-interface {v0, p1, v1}, Llyiahf/vczjk/h32;->OooO00o(Llyiahf/vczjk/u94;I)V

    return-void
.end method
