.class public final Llyiahf/vczjk/qp3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/uca;
.implements Llyiahf/vczjk/uj6;
.implements Llyiahf/vczjk/kq2;
.implements Llyiahf/vczjk/apa;
.implements Llyiahf/vczjk/rw;
.implements Llyiahf/vczjk/uw;
.implements Llyiahf/vczjk/sl5;
.implements Llyiahf/vczjk/ac3;
.implements Llyiahf/vczjk/a06;
.implements Llyiahf/vczjk/v17;
.implements Llyiahf/vczjk/o16;
.implements Llyiahf/vczjk/xx6;
.implements Llyiahf/vczjk/m98;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/qp3;

.field public static final OooOOO0:Llyiahf/vczjk/jo;

.field public static OooOOOO:Llyiahf/vczjk/ii7;

.field public static final OooOOOo:Llyiahf/vczjk/qp3;

.field public static final OooOOo:Llyiahf/vczjk/qp3;

.field public static final OooOOo0:Llyiahf/vczjk/qp3;

.field public static final OooOOoo:Llyiahf/vczjk/qp3;

.field public static final OooOo0:Llyiahf/vczjk/qp3;

.field public static final OooOo00:Llyiahf/vczjk/qp3;

.field public static final OooOo0O:Llyiahf/vczjk/qp3;

.field public static OooOo0o:Llyiahf/vczjk/qp3;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/jo;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    new-instance v0, Llyiahf/vczjk/qp3;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/qp3;->OooOOO:Llyiahf/vczjk/qp3;

    new-instance v0, Llyiahf/vczjk/qp3;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/qp3;->OooOOOo:Llyiahf/vczjk/qp3;

    new-instance v0, Llyiahf/vczjk/qp3;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/qp3;->OooOOo0:Llyiahf/vczjk/qp3;

    new-instance v0, Llyiahf/vczjk/qp3;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/qp3;->OooOOo:Llyiahf/vczjk/qp3;

    new-instance v0, Llyiahf/vczjk/qp3;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/qp3;->OooOOoo:Llyiahf/vczjk/qp3;

    new-instance v0, Llyiahf/vczjk/qp3;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/qp3;->OooOo00:Llyiahf/vczjk/qp3;

    new-instance v0, Llyiahf/vczjk/qp3;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/qp3;->OooOo0:Llyiahf/vczjk/qp3;

    new-instance v0, Llyiahf/vczjk/qp3;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/qp3;->OooOo0O:Llyiahf/vczjk/qp3;

    return-void
.end method

.method public static OooOo(Ljava/lang/String;)Llyiahf/vczjk/c80;
    .locals 6

    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    goto :goto_2

    :cond_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v0

    add-int/lit8 v2, v0, -0x1

    move v3, v2

    :goto_0
    const/4 v4, -0x1

    if-le v3, v4, :cond_3

    invoke-virtual {p0, v3}, Ljava/lang/String;->charAt(I)C

    move-result v4

    invoke-static {v4}, Ljava/lang/Character;->isDigit(C)Z

    move-result v4

    if-eqz v4, :cond_2

    add-int/lit8 v4, v3, 0x1

    const/4 v5, 0x0

    :try_start_0
    invoke-virtual {p0, v5, v4}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v5

    invoke-static {v5}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    move-result v5

    if-ne v3, v2, :cond_1

    move-object p0, v1

    goto :goto_1

    :cond_1
    invoke-virtual {p0, v4, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object p0

    :goto_1
    new-instance v0, Llyiahf/vczjk/c80;

    invoke-direct {v0, v5, p0}, Llyiahf/vczjk/c80;-><init>(FLjava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :cond_2
    add-int/lit8 v3, v3, -0x1

    goto :goto_0

    :catch_0
    :cond_3
    :goto_2
    return-object v1
.end method

.method public static final OooOo0(ILjava/lang/String;)Llyiahf/vczjk/kca;
    .locals 2

    sget-object p0, Llyiahf/vczjk/poa;->OooOo0O:Ljava/util/WeakHashMap;

    new-instance p0, Llyiahf/vczjk/kca;

    new-instance v0, Llyiahf/vczjk/e14;

    const/4 v1, 0x0

    invoke-direct {v0, v1, v1, v1, v1}, Llyiahf/vczjk/e14;-><init>(IIII)V

    invoke-direct {p0, v0, p1}, Llyiahf/vczjk/kca;-><init>(Llyiahf/vczjk/e14;Ljava/lang/String;)V

    return-object p0
.end method

.method public static final OooOo00(ILjava/lang/String;)Llyiahf/vczjk/xh;
    .locals 1

    sget-object v0, Llyiahf/vczjk/poa;->OooOo0O:Ljava/util/WeakHashMap;

    new-instance v0, Llyiahf/vczjk/xh;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/xh;-><init>(ILjava/lang/String;)V

    return-object v0
.end method

.method public static OooOo0O(Ljava/lang/String;Llyiahf/vczjk/ib3;I)Landroid/graphics/Typeface;
    .locals 1

    if-nez p2, :cond_1

    sget-object v0, Llyiahf/vczjk/ib3;->OooOOoo:Llyiahf/vczjk/ib3;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    if-eqz p0, :cond_0

    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v0

    if-nez v0, :cond_1

    :cond_0
    sget-object p0, Landroid/graphics/Typeface;->DEFAULT:Landroid/graphics/Typeface;

    return-object p0

    :cond_1
    invoke-static {p1, p2}, Llyiahf/vczjk/so8;->OooOoo(Llyiahf/vczjk/ib3;I)I

    move-result p1

    if-eqz p0, :cond_3

    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result p2

    if-nez p2, :cond_2

    goto :goto_0

    :cond_2
    invoke-static {p0, p1}, Landroid/graphics/Typeface;->create(Ljava/lang/String;I)Landroid/graphics/Typeface;

    move-result-object p0

    return-object p0

    :cond_3
    :goto_0
    invoke-static {p1}, Landroid/graphics/Typeface;->defaultFromStyle(I)Landroid/graphics/Typeface;

    move-result-object p0

    return-object p0
.end method

.method public static OooOo0o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/poa;
    .locals 4

    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0o:Llyiahf/vczjk/l39;

    check-cast p0, Llyiahf/vczjk/zf1;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/view/View;

    sget-object v1, Llyiahf/vczjk/poa;->OooOo0O:Ljava/util/WeakHashMap;

    monitor-enter v1

    :try_start_0
    invoke-virtual {v1, v0}, Ljava/util/WeakHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_0

    new-instance v2, Llyiahf/vczjk/poa;

    invoke-direct {v2, v0}, Llyiahf/vczjk/poa;-><init>(Landroid/view/View;)V

    invoke-virtual {v1, v0, v2}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    :cond_0
    :goto_0
    check-cast v2, Llyiahf/vczjk/poa;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v1

    invoke-virtual {p0, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {p0, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v1, v3

    invoke-virtual {p0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v1, :cond_1

    sget-object v1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v3, v1, :cond_2

    :cond_1
    new-instance v3, Llyiahf/vczjk/ooa;

    invoke-direct {v3, v2, v0}, Llyiahf/vczjk/ooa;-><init>(Llyiahf/vczjk/poa;Landroid/view/View;)V

    invoke-virtual {p0, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2
    check-cast v3, Llyiahf/vczjk/oe3;

    invoke-static {v2, v3, p0}, Llyiahf/vczjk/c6a;->OooOO0o(Ljava/lang/Object;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;)V

    return-object v2

    :goto_1
    monitor-exit v1

    throw p0
.end method

.method public static final OooOoO0(Landroid/content/Context;)Llyiahf/vczjk/ii7;
    .locals 2

    sget-object v0, Llyiahf/vczjk/qp3;->OooOOOO:Llyiahf/vczjk/ii7;

    if-nez v0, :cond_1

    sget-object v1, Llyiahf/vczjk/qp3;->OooOOO:Llyiahf/vczjk/qp3;

    monitor-enter v1

    :try_start_0
    sget-object v0, Llyiahf/vczjk/qp3;->OooOOOO:Llyiahf/vczjk/ii7;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v0, :cond_0

    monitor-exit v1

    return-object v0

    :cond_0
    :try_start_1
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    invoke-static {p0}, Llyiahf/vczjk/m6a;->Oooo00o(Landroid/content/Context;)Llyiahf/vczjk/ii7;

    move-result-object p0

    sput-object p0, Llyiahf/vczjk/qp3;->OooOOOO:Llyiahf/vczjk/ii7;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v1

    return-object p0

    :catchall_0
    move-exception p0

    :try_start_2
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    throw p0

    :cond_1
    return-object v0
.end method


# virtual methods
.method public OooO(Llyiahf/vczjk/jl5;)Z
    .locals 7

    const/4 v0, 0x0

    move-object v1, v0

    :goto_0
    const/4 v2, 0x0

    if-eqz p1, :cond_7

    instance-of v3, p1, Llyiahf/vczjk/ny6;

    if-eqz v3, :cond_0

    check-cast p1, Llyiahf/vczjk/ny6;

    invoke-interface {p1}, Llyiahf/vczjk/ny6;->Oooo0O0()V

    goto :goto_3

    :cond_0
    iget v3, p1, Llyiahf/vczjk/jl5;->OooOOOO:I

    const/16 v4, 0x10

    and-int/2addr v3, v4

    if-eqz v3, :cond_6

    instance-of v3, p1, Llyiahf/vczjk/m52;

    if-eqz v3, :cond_6

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/m52;

    iget-object v3, v3, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    :goto_1
    const/4 v5, 0x1

    if-eqz v3, :cond_5

    iget v6, v3, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v6, v4

    if-eqz v6, :cond_4

    add-int/lit8 v2, v2, 0x1

    if-ne v2, v5, :cond_1

    move-object p1, v3

    goto :goto_2

    :cond_1
    if-nez v1, :cond_2

    new-instance v1, Llyiahf/vczjk/ws5;

    new-array v5, v4, [Llyiahf/vczjk/jl5;

    invoke-direct {v1, v5}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_2
    if-eqz p1, :cond_3

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object p1, v0

    :cond_3
    invoke-virtual {v1, v3}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_4
    :goto_2
    iget-object v3, v3, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_1

    :cond_5
    if-ne v2, v5, :cond_6

    goto :goto_0

    :cond_6
    :goto_3
    invoke-static {v1}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object p1

    goto :goto_0

    :cond_7
    return v2
.end method

.method public OooO00o(Llyiahf/vczjk/bh3;Llyiahf/vczjk/ib3;I)Landroid/graphics/Typeface;
    .locals 4

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p2, Llyiahf/vczjk/ib3;->OooOOO0:I

    div-int/lit8 p1, p1, 0x64

    const-string v0, "sans-serif"

    const/4 v1, 0x2

    if-ltz p1, :cond_0

    if-ge p1, v1, :cond_0

    const-string p1, "sans-serif-thin"

    goto :goto_1

    :cond_0
    const/4 v2, 0x4

    if-gt v1, p1, :cond_1

    if-ge p1, v2, :cond_1

    const-string p1, "sans-serif-light"

    goto :goto_1

    :cond_1
    if-ne p1, v2, :cond_3

    :cond_2
    :goto_0
    move-object p1, v0

    goto :goto_1

    :cond_3
    const/4 v1, 0x5

    if-ne p1, v1, :cond_4

    const-string p1, "sans-serif-medium"

    goto :goto_1

    :cond_4
    const/4 v1, 0x6

    const/16 v2, 0x8

    if-gt v1, p1, :cond_5

    if-ge p1, v2, :cond_5

    goto :goto_0

    :cond_5
    if-gt v2, p1, :cond_2

    const/16 v1, 0xb

    if-ge p1, v1, :cond_2

    const-string p1, "sans-serif-black"

    :goto_1
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v1

    const/4 v2, 0x0

    if-nez v1, :cond_6

    goto :goto_2

    :cond_6
    invoke-static {p1, p2, p3}, Llyiahf/vczjk/qp3;->OooOo0O(Ljava/lang/String;Llyiahf/vczjk/ib3;I)Landroid/graphics/Typeface;

    move-result-object p1

    sget-object v1, Landroid/graphics/Typeface;->DEFAULT:Landroid/graphics/Typeface;

    invoke-static {p2, p3}, Llyiahf/vczjk/so8;->OooOoo(Llyiahf/vczjk/ib3;I)I

    move-result v3

    invoke-static {v1, v3}, Landroid/graphics/Typeface;->create(Landroid/graphics/Typeface;I)Landroid/graphics/Typeface;

    move-result-object v1

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_7

    invoke-static {v2, p2, p3}, Llyiahf/vczjk/qp3;->OooOo0O(Ljava/lang/String;Llyiahf/vczjk/ib3;I)Landroid/graphics/Typeface;

    move-result-object v1

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_7

    move-object v2, p1

    :cond_7
    :goto_2
    if-nez v2, :cond_8

    invoke-static {v0, p2, p3}, Llyiahf/vczjk/qp3;->OooOo0O(Ljava/lang/String;Llyiahf/vczjk/ib3;I)Landroid/graphics/Typeface;

    move-result-object p1

    return-object p1

    :cond_8
    return-object v2
.end method

.method public OooO0O0(Llyiahf/vczjk/eo0;)V
    .locals 3

    const-string v0, "descriptor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Cannot infer visibility for "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public OooO0OO(Llyiahf/vczjk/ie7;)Ljava/lang/Object;
    .locals 0

    iget-object p1, p1, Llyiahf/vczjk/ie7;->OooO00o:Llyiahf/vczjk/rm4;

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public OooO0o(Llyiahf/vczjk/ro4;JLlyiahf/vczjk/eo3;IZ)V
    .locals 0

    invoke-virtual/range {p1 .. p6}, Llyiahf/vczjk/ro4;->OooOoOO(JLlyiahf/vczjk/eo3;IZ)V

    return-void
.end method

.method public OooO0o0()I
    .locals 1

    const/16 v0, 0x10

    return v0
.end method

.method public OooO0oO()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public OooO0oo(Landroidx/preference/Preference;)Ljava/lang/CharSequence;
    .locals 3

    check-cast p1, Landroidx/preference/ListPreference;

    iget-object v0, p1, Landroidx/preference/ListPreference;->Oooooo:Ljava/lang/String;

    invoke-virtual {p1, v0}, Landroidx/preference/ListPreference;->OooOoOO(Ljava/lang/String;)I

    move-result v0

    const/4 v1, 0x0

    if-ltz v0, :cond_0

    iget-object v2, p1, Landroidx/preference/ListPreference;->OooooOo:[Ljava/lang/CharSequence;

    if-eqz v2, :cond_0

    aget-object v0, v2, v0

    goto :goto_0

    :cond_0
    move-object v0, v1

    :goto_0
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    if-eqz v0, :cond_1

    sget v0, Landroidx/preference/R$string;->not_set:I

    iget-object p1, p1, Landroidx/preference/Preference;->OooOOO0:Landroid/content/Context;

    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_1
    iget-object v0, p1, Landroidx/preference/ListPreference;->Oooooo:Ljava/lang/String;

    invoke-virtual {p1, v0}, Landroidx/preference/ListPreference;->OooOoOO(Ljava/lang/String;)I

    move-result v0

    if-ltz v0, :cond_2

    iget-object p1, p1, Landroidx/preference/ListPreference;->OooooOo:[Ljava/lang/CharSequence;

    if-eqz p1, :cond_2

    aget-object p1, p1, v0

    return-object p1

    :cond_2
    return-object v1
.end method

.method public OooOO0(Llyiahf/vczjk/ro4;)Z
    .locals 0

    const/4 p1, 0x1

    return p1
.end method

.method public OooOO0O(Landroid/app/Application;)Ljava/util/Comparator;
    .locals 1

    new-instance p1, Llyiahf/vczjk/h93;

    const/16 v0, 0xd

    invoke-direct {p1, v0}, Llyiahf/vczjk/h93;-><init>(I)V

    return-object p1
.end method

.method public OooOO0o(Landroid/content/Context;Llyiahf/vczjk/g62;)Llyiahf/vczjk/zoa;
    .locals 5

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "densityCompatHelper"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v0, p1

    :goto_0
    instance-of v1, v0, Landroid/content/ContextWrapper;

    const-string v2, " is not a UiContext"

    if-eqz v1, :cond_5

    instance-of v1, v0, Landroid/app/Activity;

    if-eqz v1, :cond_0

    goto :goto_1

    :cond_0
    instance-of v3, v0, Landroid/inputmethodservice/InputMethodService;

    if-eqz v3, :cond_1

    goto :goto_1

    :cond_1
    move-object v3, v0

    check-cast v3, Landroid/content/ContextWrapper;

    invoke-virtual {v3}, Landroid/content/ContextWrapper;->getBaseContext()Landroid/content/Context;

    move-result-object v4

    if-nez v4, :cond_4

    :goto_1
    if-eqz v1, :cond_2

    check-cast v0, Landroid/app/Activity;

    invoke-virtual {p0, v0, p2}, Llyiahf/vczjk/qp3;->OooOOOO(Landroid/app/Activity;Llyiahf/vczjk/g62;)Llyiahf/vczjk/zoa;

    move-result-object p1

    return-object p1

    :cond_2
    instance-of v0, v0, Landroid/inputmethodservice/InputMethodService;

    if-eqz v0, :cond_3

    const-string v0, "window"

    invoke-virtual {p1, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    const-string v1, "null cannot be cast to non-null type android.view.WindowManager"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Landroid/view/WindowManager;

    invoke-interface {v0}, Landroid/view/WindowManager;->getDefaultDisplay()Landroid/view/Display;

    move-result-object v0

    const-string v1, "getDefaultDisplay(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Landroid/graphics/Point;

    invoke-direct {v1}, Landroid/graphics/Point;-><init>()V

    invoke-virtual {v0, v1}, Landroid/view/Display;->getRealSize(Landroid/graphics/Point;)V

    new-instance v0, Landroid/graphics/Rect;

    iget v2, v1, Landroid/graphics/Point;->x:I

    iget v1, v1, Landroid/graphics/Point;->y:I

    const/4 v3, 0x0

    invoke-direct {v0, v3, v3, v2, v1}, Landroid/graphics/Rect;-><init>(IIII)V

    new-instance v1, Llyiahf/vczjk/zoa;

    invoke-interface {p2, p1}, Llyiahf/vczjk/g62;->OooO00o(Landroid/content/Context;)F

    move-result p1

    invoke-direct {v1, v0, p1}, Llyiahf/vczjk/zoa;-><init>(Landroid/graphics/Rect;F)V

    return-object v1

    :cond_3
    new-instance p2, Ljava/lang/IllegalArgumentException;

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_4
    invoke-virtual {v3}, Landroid/content/ContextWrapper;->getBaseContext()Landroid/content/Context;

    move-result-object v0

    const-string v1, "getBaseContext(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_0

    :cond_5
    new-instance p2, Ljava/lang/IllegalArgumentException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Context "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2
.end method

.method public OooOOO(Llyiahf/vczjk/rb4;F)Ljava/lang/Object;
    .locals 0

    invoke-static {p1}, Llyiahf/vczjk/sc4;->OooO0Oo(Llyiahf/vczjk/rb4;)F

    move-result p1

    mul-float/2addr p1, p2

    invoke-static {p1}, Ljava/lang/Math;->round(F)I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1
.end method

.method public OooOOO0(Llyiahf/vczjk/ib3;I)Landroid/graphics/Typeface;
    .locals 1

    const/4 v0, 0x0

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/qp3;->OooOo0O(Ljava/lang/String;Llyiahf/vczjk/ib3;I)Landroid/graphics/Typeface;

    move-result-object p1

    return-object p1
.end method

.method public OooOOOO(Landroid/app/Activity;Llyiahf/vczjk/g62;)Llyiahf/vczjk/zoa;
    .locals 3

    const-string v0, "activity"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "densityCompatHelper"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/zoa;

    new-instance v1, Llyiahf/vczjk/ug0;

    sget-object v2, Llyiahf/vczjk/wg0;->OooO0O0:Llyiahf/vczjk/vg0;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {}, Llyiahf/vczjk/vg0;->OooO00o()Llyiahf/vczjk/wg0;

    move-result-object v2

    invoke-interface {v2, p1}, Llyiahf/vczjk/wg0;->OooO00o(Landroid/app/Activity;)Landroid/graphics/Rect;

    move-result-object v2

    invoke-direct {v1, v2}, Llyiahf/vczjk/ug0;-><init>(Landroid/graphics/Rect;)V

    invoke-interface {p2, p1}, Llyiahf/vczjk/g62;->OooO00o(Landroid/content/Context;)F

    move-result p1

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/zoa;-><init>(Llyiahf/vczjk/ug0;F)V

    return-object v0
.end method

.method public OooOOOo(Llyiahf/vczjk/by0;Ljava/util/ArrayList;)V
    .locals 3

    const-string v0, "descriptor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Incomplete hierarchy for class "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-interface {p1}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object p1

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, ", unresolved classes "

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public OooOOo(IIII)V
    .locals 0

    return-void
.end method

.method public OooOOo0(IIZI)V
    .locals 0

    return-void
.end method

.method public OooOOoo(Landroid/app/Application;Llyiahf/vczjk/wu;)Ljava/lang/String;
    .locals 0

    iget-object p1, p2, Llyiahf/vczjk/wu;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-wide p1, p1, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->firstInstallTime:J

    invoke-static {p1, p2}, Lgithub/tornaco/android/thanos/core/util/DateUtils;->formatLongForMessageTime(J)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public OooOoO(Llyiahf/vczjk/n62;F)V
    .locals 4

    iget-object v0, p1, Llyiahf/vczjk/n62;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroid/graphics/drawable/Drawable;

    check-cast v0, Llyiahf/vczjk/pv7;

    iget-object v1, p1, Llyiahf/vczjk/n62;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Landroidx/cardview/widget/CardView;

    invoke-virtual {v1}, Landroidx/cardview/widget/CardView;->getUseCompatPadding()Z

    move-result v2

    invoke-virtual {v1}, Landroidx/cardview/widget/CardView;->getPreventCornerOverlap()Z

    move-result v1

    iget v3, v0, Llyiahf/vczjk/pv7;->OooO0o0:F

    cmpl-float v3, p2, v3

    if-nez v3, :cond_0

    iget-boolean v3, v0, Llyiahf/vczjk/pv7;->OooO0o:Z

    if-ne v3, v2, :cond_0

    iget-boolean v3, v0, Llyiahf/vczjk/pv7;->OooO0oO:Z

    if-ne v3, v1, :cond_0

    goto :goto_0

    :cond_0
    iput p2, v0, Llyiahf/vczjk/pv7;->OooO0o0:F

    iput-boolean v2, v0, Llyiahf/vczjk/pv7;->OooO0o:Z

    iput-boolean v1, v0, Llyiahf/vczjk/pv7;->OooO0oO:Z

    const/4 p2, 0x0

    invoke-virtual {v0, p2}, Llyiahf/vczjk/pv7;->OooO0O0(Landroid/graphics/Rect;)V

    invoke-virtual {v0}, Landroid/graphics/drawable/Drawable;->invalidateSelf()V

    :goto_0
    invoke-virtual {p0, p1}, Llyiahf/vczjk/qp3;->OooOoOO(Llyiahf/vczjk/n62;)V

    return-void
.end method

.method public OooOoOO(Llyiahf/vczjk/n62;)V
    .locals 5

    iget-object v0, p1, Llyiahf/vczjk/n62;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Landroidx/cardview/widget/CardView;

    invoke-virtual {v0}, Landroidx/cardview/widget/CardView;->getUseCompatPadding()Z

    move-result v0

    if-nez v0, :cond_0

    const/4 v0, 0x0

    invoke-virtual {p1, v0, v0, v0, v0}, Llyiahf/vczjk/n62;->o0000O00(IIII)V

    return-void

    :cond_0
    iget-object v0, p1, Llyiahf/vczjk/n62;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroid/graphics/drawable/Drawable;

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/pv7;

    iget v1, v1, Llyiahf/vczjk/pv7;->OooO0o0:F

    check-cast v0, Llyiahf/vczjk/pv7;

    iget v0, v0, Llyiahf/vczjk/pv7;->OooO00o:F

    iget-object v2, p1, Llyiahf/vczjk/n62;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Landroidx/cardview/widget/CardView;

    invoke-virtual {v2}, Landroidx/cardview/widget/CardView;->getPreventCornerOverlap()Z

    move-result v3

    invoke-static {v1, v0, v3}, Llyiahf/vczjk/rv7;->OooO00o(FFZ)F

    move-result v3

    float-to-double v3, v3

    invoke-static {v3, v4}, Ljava/lang/Math;->ceil(D)D

    move-result-wide v3

    double-to-int v3, v3

    invoke-virtual {v2}, Landroidx/cardview/widget/CardView;->getPreventCornerOverlap()Z

    move-result v2

    invoke-static {v1, v0, v2}, Llyiahf/vczjk/rv7;->OooO0O0(FFZ)F

    move-result v0

    float-to-double v0, v0

    invoke-static {v0, v1}, Ljava/lang/Math;->ceil(D)D

    move-result-wide v0

    double-to-int v0, v0

    invoke-virtual {p1, v3, v0, v3, v0}, Llyiahf/vczjk/n62;->o0000O00(IIII)V

    return-void
.end method

.method public Oooooo0(Landroid/content/Context;)Ljava/util/Comparator;
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/h93;

    const/16 v0, 0xc

    invoke-direct {p1, v0}, Llyiahf/vczjk/h93;-><init>(I)V

    return-object p1
.end method

.method public o00Oo0(Landroid/content/Context;Llyiahf/vczjk/xw;)Ljava/lang/String;
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "model"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p2, Llyiahf/vczjk/xw;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-wide p1, p1, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->firstInstallTime:J

    invoke-static {p1, p2}, Lgithub/tornaco/android/thanos/core/util/DateUtils;->formatLongForMessageTime(J)Ljava/lang/String;

    move-result-object p1

    const-string p2, "formatLongForMessageTime(...)"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1
.end method

.method public shutdown()V
    .locals 0

    return-void
.end method
