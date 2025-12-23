.class public abstract Llyiahf/vczjk/ds4;
.super Llyiahf/vczjk/kg5;
.source "SourceFile"


# static fields
.field public static final synthetic OooOOO0:[Llyiahf/vczjk/th4;


# instance fields
.field public final OooO:Llyiahf/vczjk/o45;

.field public final OooO0O0:Llyiahf/vczjk/ld9;

.field public final OooO0OO:Llyiahf/vczjk/rr4;

.field public final OooO0Oo:Llyiahf/vczjk/j45;

.field public final OooO0o:Llyiahf/vczjk/l45;

.field public final OooO0o0:Llyiahf/vczjk/o45;

.field public final OooO0oO:Llyiahf/vczjk/r60;

.field public final OooO0oo:Llyiahf/vczjk/l45;

.field public final OooOO0:Llyiahf/vczjk/o45;

.field public final OooOO0O:Llyiahf/vczjk/o45;

.field public final OooOO0o:Llyiahf/vczjk/l45;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/ds4;

    const-string v2, "functionNamesLazy"

    const-string v3, "getFunctionNamesLazy()Ljava/util/Set;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v2, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const-string v3, "propertyNamesLazy"

    const-string v5, "getPropertyNamesLazy()Ljava/util/Set;"

    invoke-static {v1, v3, v5, v4, v2}, Llyiahf/vczjk/u81;->OooOOOo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/zm7;)Llyiahf/vczjk/mh4;

    move-result-object v3

    const-string v5, "classNamesLazy"

    const-string v6, "getClassNamesLazy()Ljava/util/Set;"

    invoke-static {v1, v5, v6, v4, v2}, Llyiahf/vczjk/u81;->OooOOOo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/zm7;)Llyiahf/vczjk/mh4;

    move-result-object v1

    const/4 v2, 0x3

    new-array v2, v2, [Llyiahf/vczjk/th4;

    aput-object v0, v2, v4

    const/4 v0, 0x1

    aput-object v3, v2, v0

    const/4 v0, 0x2

    aput-object v1, v2, v0

    sput-object v2, Llyiahf/vczjk/ds4;->OooOOO0:[Llyiahf/vczjk/th4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/rr4;)V
    .locals 1

    const-string v0, "c"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    iput-object p2, p0, Llyiahf/vczjk/ds4;->OooO0OO:Llyiahf/vczjk/rr4;

    iget-object p1, p1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s64;

    iget-object p1, p1, Llyiahf/vczjk/s64;->OooO00o:Llyiahf/vczjk/q45;

    new-instance p2, Llyiahf/vczjk/as4;

    const/4 v0, 0x0

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/as4;-><init>(Llyiahf/vczjk/ds4;I)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/j45;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/o45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v0, p0, Llyiahf/vczjk/ds4;->OooO0Oo:Llyiahf/vczjk/j45;

    new-instance p2, Llyiahf/vczjk/as4;

    const/4 v0, 0x1

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/as4;-><init>(Llyiahf/vczjk/ds4;I)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/o45;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v0, p0, Llyiahf/vczjk/ds4;->OooO0o0:Llyiahf/vczjk/o45;

    new-instance p2, Llyiahf/vczjk/bs4;

    const/4 v0, 0x0

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/bs4;-><init>(Llyiahf/vczjk/ds4;I)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/q45;->OooO0O0(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/l45;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/ds4;->OooO0o:Llyiahf/vczjk/l45;

    new-instance p2, Llyiahf/vczjk/bs4;

    const/4 v0, 0x1

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/bs4;-><init>(Llyiahf/vczjk/ds4;I)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/q45;->OooO0OO(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/r60;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/ds4;->OooO0oO:Llyiahf/vczjk/r60;

    new-instance p2, Llyiahf/vczjk/bs4;

    const/4 v0, 0x2

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/bs4;-><init>(Llyiahf/vczjk/ds4;I)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/q45;->OooO0O0(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/l45;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/ds4;->OooO0oo:Llyiahf/vczjk/l45;

    new-instance p2, Llyiahf/vczjk/as4;

    const/4 v0, 0x2

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/as4;-><init>(Llyiahf/vczjk/ds4;I)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/o45;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v0, p0, Llyiahf/vczjk/ds4;->OooO:Llyiahf/vczjk/o45;

    new-instance p2, Llyiahf/vczjk/as4;

    const/4 v0, 0x3

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/as4;-><init>(Llyiahf/vczjk/ds4;I)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/o45;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v0, p0, Llyiahf/vczjk/ds4;->OooOO0:Llyiahf/vczjk/o45;

    new-instance p2, Llyiahf/vczjk/as4;

    const/4 v0, 0x4

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/as4;-><init>(Llyiahf/vczjk/ds4;I)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/o45;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v0, p0, Llyiahf/vczjk/ds4;->OooOO0O:Llyiahf/vczjk/o45;

    new-instance p2, Llyiahf/vczjk/bs4;

    const/4 v0, 0x3

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/bs4;-><init>(Llyiahf/vczjk/ds4;I)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/q45;->OooO0O0(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/l45;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ds4;->OooOO0o:Llyiahf/vczjk/l45;

    return-void
.end method

.method public static OooOO0o(Llyiahf/vczjk/lm7;Llyiahf/vczjk/ld9;)Llyiahf/vczjk/uk4;
    .locals 4

    const-string v0, "method"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/lm7;->OooO0O0()Ljava/lang/reflect/Member;

    move-result-object v0

    check-cast v0, Ljava/lang/reflect/Method;

    invoke-virtual {v0}, Ljava/lang/reflect/Method;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v0

    const-string v1, "getDeclaringClass(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Ljava/lang/Class;->isAnnotation()Z

    move-result v0

    sget-object v1, Llyiahf/vczjk/j5a;->OooOOO:Llyiahf/vczjk/j5a;

    const/4 v2, 0x6

    const/4 v3, 0x0

    invoke-static {v1, v0, v3, v2}, Llyiahf/vczjk/nqa;->OoooO00(Llyiahf/vczjk/j5a;ZLlyiahf/vczjk/hs4;I)Llyiahf/vczjk/a74;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/lm7;->OooO0o()Llyiahf/vczjk/pm7;

    move-result-object p0

    iget-object p1, p1, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/uqa;

    invoke-virtual {p1, p0, v0}, Llyiahf/vczjk/uqa;->Oooo0oo(Llyiahf/vczjk/y64;Llyiahf/vczjk/a74;)Llyiahf/vczjk/uk4;

    move-result-object p0

    return-object p0
.end method

.method public static OooOo0(Llyiahf/vczjk/ld9;Llyiahf/vczjk/tf3;Ljava/util/List;)Llyiahf/vczjk/pc0;
    .locals 18

    move-object/from16 v0, p0

    invoke-static/range {p2 .. p2}, Llyiahf/vczjk/d21;->o0000Oo0(Ljava/util/List;)Llyiahf/vczjk/uy;

    move-result-object v1

    new-instance v2, Ljava/util/ArrayList;

    const/16 v3, 0xa

    invoke-static {v1, v3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v1}, Llyiahf/vczjk/uy;->iterator()Ljava/util/Iterator;

    move-result-object v1

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    move-object v5, v1

    check-cast v5, Llyiahf/vczjk/zi2;

    iget-object v6, v5, Llyiahf/vczjk/zi2;->OooOOO:Ljava/util/Iterator;

    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_7

    invoke-virtual {v5}, Llyiahf/vczjk/zi2;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/kx3;

    iget v9, v5, Llyiahf/vczjk/kx3;->OooO00o:I

    iget-object v5, v5, Llyiahf/vczjk/kx3;->OooO0O0:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/rm7;

    invoke-static {v0, v5}, Llyiahf/vczjk/dn8;->o00oO0o(Llyiahf/vczjk/ld9;Llyiahf/vczjk/b64;)Llyiahf/vczjk/lr4;

    move-result-object v10

    sget-object v6, Llyiahf/vczjk/j5a;->OooOOO:Llyiahf/vczjk/j5a;

    const/4 v7, 0x7

    const/4 v8, 0x0

    invoke-static {v6, v3, v8, v7}, Llyiahf/vczjk/nqa;->OoooO00(Llyiahf/vczjk/j5a;ZLlyiahf/vczjk/hs4;I)Llyiahf/vczjk/a74;

    move-result-object v6

    iget-object v7, v0, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/s64;

    iget-object v11, v5, Llyiahf/vczjk/rm7;->OooO00o:Llyiahf/vczjk/pm7;

    iget-boolean v12, v5, Llyiahf/vczjk/rm7;->OooO0Oo:Z

    const/4 v13, 0x1

    iget-object v14, v0, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    check-cast v14, Llyiahf/vczjk/uqa;

    iget-object v15, v7, Llyiahf/vczjk/s64;->OooOOOO:Llyiahf/vczjk/dm5;

    if-eqz v12, :cond_2

    instance-of v12, v11, Llyiahf/vczjk/wl7;

    if-eqz v12, :cond_0

    check-cast v11, Llyiahf/vczjk/wl7;

    goto :goto_1

    :cond_0
    move-object v11, v8

    :goto_1
    if-eqz v11, :cond_1

    invoke-virtual {v14, v11, v6, v13}, Llyiahf/vczjk/uqa;->Oooo0oO(Llyiahf/vczjk/wl7;Llyiahf/vczjk/a74;Z)Llyiahf/vczjk/iaa;

    move-result-object v6

    iget-object v11, v15, Llyiahf/vczjk/dm5;->OooOOoo:Llyiahf/vczjk/hk4;

    invoke-virtual {v11, v6}, Llyiahf/vczjk/hk4;->OooO0o(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/uk4;

    move-result-object v11

    new-instance v12, Llyiahf/vczjk/xn6;

    invoke-direct {v12, v6, v11}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_2

    :cond_1
    new-instance v0, Ljava/lang/AssertionError;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Vararg parameter should be an array: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v0

    :cond_2
    invoke-virtual {v14, v11, v6}, Llyiahf/vczjk/uqa;->Oooo0oo(Llyiahf/vczjk/y64;Llyiahf/vczjk/a74;)Llyiahf/vczjk/uk4;

    move-result-object v6

    new-instance v12, Llyiahf/vczjk/xn6;

    invoke-direct {v12, v6, v8}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    :goto_2
    invoke-virtual {v12}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/uk4;

    invoke-virtual {v12}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object v11

    move-object/from16 v16, v11

    check-cast v16, Llyiahf/vczjk/uk4;

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v11

    invoke-virtual {v11}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v11

    const-string v12, "equals"

    invoke-static {v11, v12}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v11

    if-eqz v11, :cond_4

    invoke-interface/range {p2 .. p2}, Ljava/util/List;->size()I

    move-result v11

    if-ne v11, v13, :cond_4

    iget-object v11, v15, Llyiahf/vczjk/dm5;->OooOOoo:Llyiahf/vczjk/hk4;

    invoke-virtual {v11}, Llyiahf/vczjk/hk4;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v11

    invoke-virtual {v11, v6}, Llyiahf/vczjk/uk4;->equals(Ljava/lang/Object;)Z

    move-result v11

    if-eqz v11, :cond_4

    const-string v8, "other"

    invoke-static {v8}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v8

    :cond_3
    :goto_3
    move-object v12, v6

    move-object v11, v8

    goto :goto_4

    :cond_4
    iget-object v11, v5, Llyiahf/vczjk/rm7;->OooO0OO:Ljava/lang/String;

    if-eqz v11, :cond_5

    invoke-static {v11}, Llyiahf/vczjk/qt5;->OooO0Oo(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v8

    :cond_5
    if-nez v8, :cond_6

    move v4, v13

    :cond_6
    if-nez v8, :cond_3

    new-instance v8, Ljava/lang/StringBuilder;

    const-string v11, "p"

    invoke-direct {v8, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v8

    invoke-static {v8}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v8

    goto :goto_3

    :goto_4
    new-instance v6, Llyiahf/vczjk/tca;

    iget-object v7, v7, Llyiahf/vczjk/s64;->OooOO0:Llyiahf/vczjk/rp3;

    invoke-virtual {v7, v5}, Llyiahf/vczjk/rp3;->OooOo0O(Llyiahf/vczjk/k64;)Llyiahf/vczjk/hz7;

    move-result-object v17

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/4 v8, 0x0

    const/4 v13, 0x0

    move-object/from16 v7, p1

    invoke-direct/range {v6 .. v17}, Llyiahf/vczjk/tca;-><init>(Llyiahf/vczjk/co0;Llyiahf/vczjk/tca;ILlyiahf/vczjk/ko;Llyiahf/vczjk/qt5;Llyiahf/vczjk/uk4;ZZZLlyiahf/vczjk/uk4;Llyiahf/vczjk/sx8;)V

    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto/16 :goto_0

    :cond_7
    invoke-static {v2}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/pc0;

    const/4 v2, 0x4

    invoke-direct {v1, v2, v0, v4}, Llyiahf/vczjk/pc0;-><init>(ILjava/lang/Object;Z)V

    return-object v1
.end method


# virtual methods
.method public abstract OooO(Llyiahf/vczjk/e72;Llyiahf/vczjk/g13;)Ljava/util/Set;
.end method

.method public final OooO00o()Ljava/util/Set;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ds4;->OooO:Llyiahf/vczjk/o45;

    sget-object v1, Llyiahf/vczjk/ds4;->OooOOO0:[Llyiahf/vczjk/th4;

    const/4 v2, 0x0

    aget-object v1, v1, v2

    invoke-static {v0, v1}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Set;

    return-object v0
.end method

.method public final OooO0OO()Ljava/util/Set;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ds4;->OooOO0O:Llyiahf/vczjk/o45;

    sget-object v1, Llyiahf/vczjk/ds4;->OooOOO0:[Llyiahf/vczjk/th4;

    const/4 v2, 0x2

    aget-object v1, v1, v2

    invoke-static {v0, v1}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Set;

    return-object v0
.end method

.method public OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;
    .locals 1

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "location"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/ds4;->OooO00o()Ljava/util/Set;

    move-result-object p2

    invoke-interface {p2, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result p2

    if-nez p2, :cond_0

    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1

    :cond_0
    iget-object p2, p0, Llyiahf/vczjk/ds4;->OooO0oo:Llyiahf/vczjk/l45;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/l45;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Collection;

    return-object p1
.end method

.method public OooO0o(Llyiahf/vczjk/e72;Llyiahf/vczjk/oe3;)Ljava/util/Collection;
    .locals 0

    const-string p2, "kindFilter"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/ds4;->OooO0Oo:Llyiahf/vczjk/j45;

    invoke-virtual {p1}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Collection;

    return-object p1
.end method

.method public OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;
    .locals 0

    const-string p2, "name"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/ds4;->OooO0oO()Ljava/util/Set;

    move-result-object p2

    invoke-interface {p2, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result p2

    if-nez p2, :cond_0

    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1

    :cond_0
    iget-object p2, p0, Llyiahf/vczjk/ds4;->OooOO0o:Llyiahf/vczjk/l45;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/l45;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Collection;

    return-object p1
.end method

.method public final OooO0oO()Ljava/util/Set;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ds4;->OooOO0:Llyiahf/vczjk/o45;

    sget-object v1, Llyiahf/vczjk/ds4;->OooOOO0:[Llyiahf/vczjk/th4;

    const/4 v2, 0x1

    aget-object v1, v1, v2

    invoke-static {v0, v1}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Set;

    return-object v0
.end method

.method public abstract OooO0oo(Llyiahf/vczjk/e72;Llyiahf/vczjk/g13;)Ljava/util/Set;
.end method

.method public OooOO0(Ljava/util/ArrayList;Llyiahf/vczjk/qt5;)V
    .locals 0

    const-string p1, "name"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-void
.end method

.method public abstract OooOO0O()Llyiahf/vczjk/c12;
.end method

.method public abstract OooOOO(Ljava/util/ArrayList;Llyiahf/vczjk/qt5;)V
.end method

.method public abstract OooOOO0(Ljava/util/LinkedHashSet;Llyiahf/vczjk/qt5;)V
.end method

.method public abstract OooOOOO(Llyiahf/vczjk/e72;)Ljava/util/Set;
.end method

.method public abstract OooOOOo()Llyiahf/vczjk/mp4;
.end method

.method public OooOOo(Llyiahf/vczjk/o64;)Z
    .locals 0

    const/4 p1, 0x1

    return p1
.end method

.method public abstract OooOOo0()Llyiahf/vczjk/v02;
.end method

.method public abstract OooOOoo(Llyiahf/vczjk/lm7;Ljava/util/ArrayList;Llyiahf/vczjk/uk4;Ljava/util/List;)Llyiahf/vczjk/cs4;
.end method

.method public final OooOo00(Llyiahf/vczjk/lm7;)Llyiahf/vczjk/o64;
    .locals 19

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    const-string v2, "method"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, v0, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    invoke-static {v2, v1}, Llyiahf/vczjk/dn8;->o00oO0o(Llyiahf/vczjk/ld9;Llyiahf/vczjk/b64;)Llyiahf/vczjk/lr4;

    move-result-object v3

    invoke-virtual {v0}, Llyiahf/vczjk/ds4;->OooOOo0()Llyiahf/vczjk/v02;

    move-result-object v4

    invoke-virtual {v1}, Llyiahf/vczjk/km7;->OooO0OO()Llyiahf/vczjk/qt5;

    move-result-object v5

    iget-object v6, v2, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/s64;

    iget-object v6, v6, Llyiahf/vczjk/s64;->OooOO0:Llyiahf/vczjk/rp3;

    invoke-virtual {v6, v1}, Llyiahf/vczjk/rp3;->OooOo0O(Llyiahf/vczjk/k64;)Llyiahf/vczjk/hz7;

    move-result-object v6

    iget-object v7, v0, Llyiahf/vczjk/ds4;->OooO0o0:Llyiahf/vczjk/o45;

    invoke-virtual {v7}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/c12;

    invoke-virtual {v1}, Llyiahf/vczjk/km7;->OooO0OO()Llyiahf/vczjk/qt5;

    move-result-object v8

    invoke-interface {v7, v8}, Llyiahf/vczjk/c12;->OooO0OO(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/om7;

    move-result-object v7

    const/4 v8, 0x0

    if-eqz v7, :cond_0

    invoke-virtual {v1}, Llyiahf/vczjk/lm7;->OooO0oO()Ljava/util/List;

    move-result-object v7

    check-cast v7, Ljava/util/ArrayList;

    invoke-virtual {v7}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v7

    if-eqz v7, :cond_0

    const/4 v7, 0x1

    goto :goto_0

    :cond_0
    move v7, v8

    :goto_0
    invoke-static {v4, v3, v5, v6, v7}, Llyiahf/vczjk/o64;->o0000oO0(Llyiahf/vczjk/v02;Llyiahf/vczjk/lr4;Llyiahf/vczjk/qt5;Llyiahf/vczjk/hz7;Z)Llyiahf/vczjk/o64;

    move-result-object v9

    const-string v3, "<this>"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v3, v2, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    iget-object v4, v2, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/s64;

    new-instance v5, Llyiahf/vczjk/rr0;

    invoke-direct {v5, v2, v9, v1, v8}, Llyiahf/vczjk/rr0;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/x02;Llyiahf/vczjk/e74;I)V

    new-instance v2, Llyiahf/vczjk/ld9;

    invoke-direct {v2, v4, v5, v3}, Llyiahf/vczjk/ld9;-><init>(Llyiahf/vczjk/s64;Llyiahf/vczjk/v4a;Llyiahf/vczjk/kp4;)V

    invoke-virtual {v1}, Llyiahf/vczjk/lm7;->OooOOO()Ljava/util/ArrayList;

    move-result-object v3

    new-instance v4, Ljava/util/ArrayList;

    const/16 v5, 0xa

    invoke-static {v3, v5}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v5

    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_1

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/qm7;

    iget-object v6, v2, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/v4a;

    invoke-interface {v6, v5}, Llyiahf/vczjk/v4a;->OooO0oO(Llyiahf/vczjk/qm7;)Llyiahf/vczjk/t4a;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_1
    invoke-virtual {v1}, Llyiahf/vczjk/lm7;->OooO0oO()Ljava/util/List;

    move-result-object v3

    invoke-static {v2, v9, v3}, Llyiahf/vczjk/ds4;->OooOo0(Llyiahf/vczjk/ld9;Llyiahf/vczjk/tf3;Ljava/util/List;)Llyiahf/vczjk/pc0;

    move-result-object v3

    invoke-static {v1, v2}, Llyiahf/vczjk/ds4;->OooOO0o(Llyiahf/vczjk/lm7;Llyiahf/vczjk/ld9;)Llyiahf/vczjk/uk4;

    move-result-object v5

    iget-object v6, v3, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    check-cast v6, Ljava/util/List;

    invoke-virtual {v0, v1, v4, v5, v6}, Llyiahf/vczjk/ds4;->OooOOoo(Llyiahf/vczjk/lm7;Ljava/util/ArrayList;Llyiahf/vczjk/uk4;Ljava/util/List;)Llyiahf/vczjk/cs4;

    move-result-object v4

    invoke-virtual {v0}, Llyiahf/vczjk/ds4;->OooOOOo()Llyiahf/vczjk/mp4;

    move-result-object v11

    sget-object v12, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    sget-object v5, Llyiahf/vczjk/yk5;->OooOOO0:Llyiahf/vczjk/wp3;

    invoke-virtual {v1}, Llyiahf/vczjk/lm7;->OooO0O0()Ljava/lang/reflect/Member;

    move-result-object v6

    check-cast v6, Ljava/lang/reflect/Method;

    invoke-virtual {v6}, Ljava/lang/reflect/Method;->getModifiers()I

    move-result v6

    invoke-static {v6}, Ljava/lang/reflect/Modifier;->isAbstract(I)Z

    move-result v6

    invoke-virtual {v1}, Llyiahf/vczjk/lm7;->OooO0O0()Ljava/lang/reflect/Member;

    move-result-object v7

    check-cast v7, Ljava/lang/reflect/Method;

    invoke-virtual {v7}, Ljava/lang/reflect/Method;->getModifiers()I

    move-result v7

    invoke-static {v7}, Ljava/lang/reflect/Modifier;->isFinal(I)Z

    move-result v7

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    if-eqz v6, :cond_2

    sget-object v5, Llyiahf/vczjk/yk5;->OooOOo0:Llyiahf/vczjk/yk5;

    :goto_2
    move-object/from16 v16, v5

    goto :goto_3

    :cond_2
    if-nez v7, :cond_3

    sget-object v5, Llyiahf/vczjk/yk5;->OooOOOo:Llyiahf/vczjk/yk5;

    goto :goto_2

    :cond_3
    sget-object v5, Llyiahf/vczjk/yk5;->OooOOO:Llyiahf/vczjk/yk5;

    goto :goto_2

    :goto_3
    invoke-virtual {v1}, Llyiahf/vczjk/km7;->OooO0o0()Llyiahf/vczjk/oO0Oo0oo;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/ht6;->OooOoOO(Llyiahf/vczjk/oO0Oo0oo;)Llyiahf/vczjk/q72;

    move-result-object v17

    sget-object v18, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    iget-object v13, v4, Llyiahf/vczjk/cs4;->OooO0OO:Ljava/util/ArrayList;

    iget-object v14, v4, Llyiahf/vczjk/cs4;->OooO0O0:Ljava/util/List;

    iget-object v15, v4, Llyiahf/vczjk/cs4;->OooO00o:Llyiahf/vczjk/uk4;

    const/4 v10, 0x0

    invoke-virtual/range {v9 .. v18}, Llyiahf/vczjk/o64;->o0000o(Llyiahf/vczjk/mp4;Llyiahf/vczjk/mp4;Ljava/util/List;Ljava/util/List;Ljava/util/List;Llyiahf/vczjk/uk4;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;Llyiahf/vczjk/bn2;)Llyiahf/vczjk/ho8;

    iget-boolean v1, v3, Llyiahf/vczjk/pc0;->OooOOO:Z

    invoke-virtual {v9, v8, v1}, Llyiahf/vczjk/o64;->o0000oOO(ZZ)V

    iget-object v1, v4, Llyiahf/vczjk/cs4;->OooO0Oo:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_4

    return-object v9

    :cond_4
    iget-object v1, v2, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/s64;

    iget-object v1, v1, Llyiahf/vczjk/s64;->OooO0o0:Llyiahf/vczjk/xj0;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Ljava/lang/UnsupportedOperationException;

    const-string v2, "Should not be called"

    invoke-direct {v1, v2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v1
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Lazy scope for "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/ds4;->OooOOo0()Llyiahf/vczjk/v02;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
